package de.tomcory.heimdall.vpn.components

import android.os.Handler
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import de.tomcory.heimdall.persistence.VpnStats
import org.pcap4j.packet.*
import timber.log.Timber
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.IOException

class DevicePollThread internal constructor(
    name: String,
    private val inputStream: FileInputStream,
    private val interrupter: FileDescriptor,
    private val outboundTrafficHandler: Handler
) : Thread(name) {

    init {
        Process.setThreadPriority(Process.THREAD_PRIORITY_FOREGROUND)
        Timber.d("Thread created")
    }

    override fun run() {
        Timber.d("Thread started")

        // allocate the buffer for a single packet and reuse it for all packets (yay, performance!)
        //TODO: actually implement a reusable buffer
        val packet = ByteArray(1500)

        // prepare to poll the inputStream
        val deviceFd = StructPollfd()
        try {
            deviceFd.fd = inputStream.fd
        } catch (e: IOException) {
            Timber.e(e, "Error getting FileDescriptor of VPN interface")
            return
        }
        deviceFd.events = OsConstants.POLLIN.toShort()

        // prepare to poll the interrupter pipe
        val interruptFd = StructPollfd()
        interruptFd.fd = interrupter
        interruptFd.events = (OsConstants.POLLHUP or OsConstants.POLLERR).toShort()

        // combine the FileDescriptors into an array for Os.poll()
        val polls = arrayOfNulls<StructPollfd>(2)
        polls[0] = deviceFd
        polls[1] = interruptFd
        Timber.d("Thread configured, polling VPN interface")

        // continuously poll until interrupted via the interrupter pipe (in which case poll() returns false)
        while (true) {
            if (!poll(packet, polls)) {
                break
            }
        }
        Timber.d("Thread shut down")
    }

    private fun poll(packetPlaceholder: ByteArray, polls: Array<StructPollfd?>): Boolean {
        val deviceFd = polls[0]
        val interruptFd = polls[1]

        // use Os.poll to poll all FileDescriptors
        var result = 0
        try {
            result = Os.poll(polls, -1)
        } catch (e: ErrnoException) {
            Timber.e(e, "Error during Os.poll()")
        }

        // unlikely to happen due to unlimited timeout on Os.poll, but still, handle timeout
        if (result == 0) {
            Timber.e("Os.poll() timed out")
            return false
        }

        // an event was written to the interrupter FileDescriptor, telling us to interrupt
        if (interruptFd!!.revents.toInt() != 0) {
            Timber.d("Told to stop VPN")
            return false
        }

        // the POLLIN event was written to the deviceFd Filedescriptor, meaning we need to read a packet from the device
        if ((deviceFd!!.revents.toInt() and OsConstants.POLLIN) != 0) {

            // read the raw bytes of the packet and forward the ByteArray to the OutboundInternetHandler
            val rawPacket = try {
                readPacket(inputStream, packetPlaceholder)
            } catch (e: IOException) {
                return false
            }

            if(rawPacket.isNotEmpty()) {
                //Timber.w("Read %s bytes from device", rawPacket.size)
                val parsedPacket = parsePacket(rawPacket)

                // forward packet to traffic handler
                if (parsedPacket != null) {
                    val transportProtocol = when(parsedPacket.payload) {
                        is TcpPacket -> 6
                        is UdpPacket -> 17
                        else -> 0
                    }
                    outboundTrafficHandler.sendMessage(outboundTrafficHandler.obtainMessage(transportProtocol, parsedPacket))
                }
            }
        }
        return true
    }

    private fun parsePacket(rawPacket: ByteArray): IpPacket? {

        // determine the IP version (4 or 6) of the packet
        val ipVersion = rawPacket[0].toInt() shr 4

        // make sure the version is correct
        if(ipVersion != 4 && ipVersion != 6) {
            Timber.e("Illegal IP version: %s", ipVersion)
            return null
        }

        // make sure we got the whole packet
        val statedLength = if(ipVersion == 4) {
            (rawPacket[2].toInt() shl 8 and 0xFFFF) + (rawPacket[3].toInt() and 0xFF)
        } else {
            (rawPacket[4].toInt() shl 8 and 0xFFFF) + (rawPacket[5].toInt() and 0xFF) + 40
        }
        if (statedLength != rawPacket.size) {
            Timber.e("Packet length mismatch (IPv%s): Stated: %s - Actual: %s - Difference: %s", ipVersion, statedLength, rawPacket.size, (rawPacket.size - statedLength))
            return null
        }

        // make sure the transport-layer protocol is TCP or UDP and drop anything else (sorry, ICMP!)
        rawPacket[if(ipVersion == 4) 9 else 6].toInt().let {
            if(it != 6 && it != 17) {
                return null
            }
        }

        // some apps keep sending packets to the general broadcast address 255.255.255.255, ignore these packets
        if(ipVersion == 4
            && rawPacket[16].toInt() == 0xFF
            && rawPacket[17].toInt() == 0xFF
            && rawPacket[18].toInt() == 0xFF
            && rawPacket[19].toInt() == 0xFF) {
            return null
        }

        // parse the packet to a pcap4j packet
        val parsedPacket: IpPacket =
            if (ipVersion == 4) {
                IpV4Packet.newPacket(rawPacket, 0, rawPacket.size)
            } else {
                IpV6Packet.newPacket(rawPacket, 0, rawPacket.size)
            }

        // update the Statistics singleton's data
        VpnStats.increaseSessionStatsOut(rawPacket)

        return parsedPacket
    }

    private fun readPacket(inputStream: FileInputStream, packet: ByteArray): ByteArray {

        // Read the outgoing packet from the input stream.
        val length = inputStream.read(packet)

        // no need to process completely empty or failed packets
        return if (length == 0) {
            ByteArray(0)
        } else {
            // continue with a copy of the packet, preventing access and garbage collection problems
            packet.copyOfRange(0, length)
        }
    }
}