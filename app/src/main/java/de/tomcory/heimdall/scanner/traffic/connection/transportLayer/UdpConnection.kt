package de.tomcory.heimdall.scanner.traffic.connection.transportLayer

import android.net.TrafficStats
import android.net.VpnService
import android.os.Handler
import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.components.DeviceWriteThread
import de.tomcory.heimdall.scanner.traffic.connection.inetLayer.IpPacketBuilder
import de.tomcory.heimdall.util.ByteUtils
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.UnknownPacket
import org.pcap4j.packet.namednumber.UdpPort
import timber.log.Timber
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.BufferOverflowException
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.*

/**
 * Represents a transport-layer connection using UDP.

 * @param initialPacket [IpPacket] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
 */
class UdpConnection internal constructor(
    componentManager: ComponentManager,
    deviceWriter: Handler,
    initialPacket: UdpPacket,
    ipPacketBuilder: IpPacketBuilder
) : TransportLayerConnection(
    deviceWriter,
    componentManager,
    localPort = initialPacket.header.srcPort,
    remotePort = initialPacket.header.dstPort,
    ipPacketBuilder
) {
    override val protocol = "UDP"
    override val id = createDatabaseEntity()
    override val selectableChannel: DatagramChannel = openChannel(ipPacketBuilder.remoteAddress, componentManager.vpnService)
    override val selectionKey = connectChannel(componentManager.selector)

    private fun openChannel(remoteAddress: InetAddress, vpnService: VpnService?): DatagramChannel {
        // open the channel now, but connect it asynchronously for better performance
        state = TransportLayerState.CONNECTING
        TrafficStats.setThreadStatsTag(42)
        val selectableChannel = DatagramChannel.open()
        vpnService?.protect(selectableChannel.socket())
        selectableChannel.configureBlocking(false)
        selectableChannel.socket().soTimeout = 0
        selectableChannel.socket().receiveBufferSize = 65535
        selectableChannel.connect(InetSocketAddress(remoteAddress, remotePort.valueAsInt()))
        state = TransportLayerState.CONNECTED
        return selectableChannel
    }

    private fun connectChannel(selector: Selector): SelectionKey? {
        // register OP_READ interest for the channel
        synchronized(ComponentManager.selectorMonitor) {
            selector.wakeup()
            val selectionKey = try {
                selectableChannel.register(selector, SelectionKey.OP_READ)
            } catch (e: Exception) {
                Timber.e(e, "%s Error registering SelectableChannel", id)
                null
            }
            selectionKey?.attach(this)
            return selectionKey
        }
    }

    override fun buildPayload(rawPayload: ByteArray): UdpPacket.Builder {
        return UdpPacket.Builder()
            .srcAddr(ipPacketBuilder.remoteAddress)
            .dstAddr(ipPacketBuilder.localAddress)
            .srcPort(remotePort as UdpPort)
            .dstPort(localPort as UdpPort)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(UnknownPacket.newPacket(rawPayload, 0, rawPayload.size).builder)
    }

    fun decodeDnsQuery(payload: ByteArray): String {
        // The query starts at byte 12, skipping the DNS header
        var index = 12

        val result = StringBuilder()

        while (index < payload.size) {
            Timber.d(ByteUtils.bytesToHex(payload))
            Timber.d("index: $index, payload: ${payload.size}")
            // Read the length byte
            val length = payload[index].toInt()

            Timber.d("length: $length")

            // If length is 0, we have reached the end of the query name
            if (length == 0) break

            // Append the label to the result string
            val label = payload.sliceArray(index + 1 until index + 1 + length).toString(Charsets.UTF_8)
            Timber.d("label: $label")
            result.append(label)

            // Move the index forward
            index += length + 1

            // If this isn't the last label, append a dot
            if (payload[index].toInt() != 0) {
                result.append('.')
            }
        }

        val res = result.toString()

        Timber.d("Decoded length %s", res.length)

        return res
    }

    fun decodeDnsResponse(payload: ByteArray): Pair<String, List<String>> {
        var index = 12

        // Parsing the Question section to extract the queried domain name
        val domainName = StringBuilder()
        while (index < payload.size) {
            val length = payload[index].toInt()
            if (length == 0) {
                index++ // Move past the null byte at the end of the domain name
                break
            }
            val label = payload.sliceArray(index + 1 until index + 1 + length).toString(Charsets.UTF_8)
            domainName.append(label)
            index += length + 1
            if (payload[index].toInt() != 0) {
                domainName.append('.')
            }
        }

        // Skipping Type and Class in Question section
        index += 4

        // Extracting IP addresses from the Answer section
        val ipAddresses = mutableListOf<String>()
        while (index < payload.size) {
            // Skipping name, type, class, and TTL
            index += 10

            // Reading data length
            val dataLength = ((payload[index].toInt() and 0xFF) shl 8) or (payload[index + 1].toInt() and 0xFF)
            index += 2

            // Assuming this is an A record, reading the IP address
            if (dataLength == 4) { // IPv4 address
                val ip = StringBuilder()
                for (i in 0 until dataLength) {
                    ip.append(payload[index + i].toInt() and 0xFF)
                    if (i < dataLength - 1) {
                        ip.append('.')
                    }
                }
                ipAddresses.add(ip.toString())
            }
            index += dataLength
        }

        return Pair(domainName.toString(), ipAddresses)
    }

    override fun wrapOutbound(payload: ByteArray) {
        Timber.w("%s Wrapping UDP out (%s bytes) to port %s", id, payload.size, remotePort.valueAsInt())
        if(remotePort.valueAsInt() == 53) {
            Timber.w("DNS")
            Timber.w(decodeDnsQuery(payload))
        }
        // if the application layer returned anything, write it to the connection's outward-facing channel
        if (payload.isNotEmpty()) {
            outBuffer.clear()
            outBuffer.put(payload)
            outBuffer.flip()
            while (outBuffer.hasRemaining()) {
                try {
                    selectableChannel.write(outBuffer)
                } catch (e: IOException) {
                    Timber.e(e, "%s Error writing to DatagramChannel, closing connection", id)
                    closeHard()
                    break
                } catch (e: BufferOverflowException) {
                    Timber.e(e, "%s Error writing to DatagramChannel, closing connection", id)
                    closeHard()
                    break
                }
            }
        }
    }

    override fun wrapInbound(payload: ByteArray) {
        Timber.w("%s Wrapping UDP in (%s bytes) from port %s", id, payload.size, remotePort.valueAsInt())
        if(remotePort.valueAsInt() == 53) {
            Timber.w("DNS")
            Timber.w(decodeDnsResponse(payload).toString())
        }
        val forwardPacket = ipPacketBuilder.buildPacket(buildPayload(payload))
        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_UDP, forwardPacket))
    }

    override fun unwrapOutbound(outgoingPacket: IpPacket) {
        Timber.w("%s Unwrapping UDP out (%s bytes)", id, outgoingPacket.payload.length())

        val payload = outgoingPacket.payload as UdpPacket? ?: return
        //TODO: below is just a placeholder for passOutboundToEncryptionLayer(payload.rawData)
        wrapOutbound(payload.rawData)
    }

    override fun unwrapInbound() {
        Timber.w("%s Unwrapping UDP in", id)
        if(selectionKey == null) {
            Timber.e("%s SelectionKey is null", id)
            state = TransportLayerState.ABORTED
            return
        }

        if (selectionKey.isReadable) {
            var bytesRead: Int
            do {
                try {
                    // read and forward the incoming data chunk by chunk
                    inBuffer.clear()
                    bytesRead = selectableChannel.read(inBuffer)
                    if (bytesRead > 0) {
                        inBuffer.flip()
                        val rawData = Arrays.copyOf(inBuffer.array(), bytesRead)

                        // pass the payload to the application layer for further processing
                        //TODO: below is just a placeholder for passInboundToEncryptionLayer(rawData)
                        wrapInbound(rawData)
                    }
                } catch (e: IOException) {
                    Timber.e(e, "%s Error reading data from DatagramChannel", id)
                    bytesRead = -1
                }
            } while (bytesRead > 0) //TODO: improve

            // no need to keep DNS connections open after the first and only packet
            if (remotePort.valueAsInt() == 53) {
                try {
                    selectableChannel.close()
                } catch (e: IOException) {
                    Timber.e(e, "%s Error closing DatagramChannel", id)
                }
                bytesRead = -1
            }

            // DatagramChannel is closed, do the same for the connection
            if (bytesRead == -1) {
                selectionKey.cancel()
                closeHard()
            }
        } else {
            Timber.e("%s UDP connection's channel triggered an event that isn't OP_READ", id)
        }
    }
}