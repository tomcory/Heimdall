package de.tomcory.heimdall.vpn.connection.transportLayer

import android.net.TrafficStats
import android.net.VpnService
import android.os.Handler
import de.tomcory.heimdall.vpn.components.ComponentManager
import de.tomcory.heimdall.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.vpn.connection.inetLayer.IpPacketBuilder
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
    manager: ComponentManager,
    deviceWriter: Handler,
    initialPacket: UdpPacket,
    ipPacketBuilder: IpPacketBuilder
) : TransportLayerConnection(
    deviceWriter,
    manager.mitmManager,
    localPort = initialPacket.header.srcPort,
    remotePort = initialPacket.header.dstPort,
    ipPacketBuilder
) {

    init {
        Timber.w("%s Creating UDP connection", id)
    }

    override val appId = manager.appFinder.getAppId(ipPacketBuilder.localAddress, ipPacketBuilder.remoteAddress, this)
    override val appPackage = manager.appFinder.getAppPackage(appId)

    override val selectableChannel: DatagramChannel = openChannel(ipPacketBuilder.remoteAddress, manager.vpnService)
    override val selectionKey = connectChannel(manager.selector)

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

    override fun wrapOutbound(payload: ByteArray) {
        //Timber.d("%s Wrapping UDP out (%s bytes)", id, payload.size)
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
        //Timber.d("%s Wrapping UDP in (%s bytes)", id, payload.size)
        val forwardPacket = ipPacketBuilder.buildPacket(buildPayload(payload))
        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_UDP, forwardPacket))
    }

    override fun unwrapOutbound(outgoingPacket: IpPacket) {
        //Timber.d("%s Unwrapping UDP out (%s bytes)", id, outgoingPacket.payload.length())
        val payload = outgoingPacket.payload as UdpPacket? ?: return
        //TODO: below is just a placeholder for passOutboundToEncryptionLayer(payload.rawData)
        wrapOutbound(payload.rawData)
    }

    override fun unwrapInbound() {
        //Timber.d("%s Unwrapping UDP in", id)
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