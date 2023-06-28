package de.tomcory.heimdall.scanner.traffic.connection.transportLayer

import android.net.VpnService
import android.os.Handler
import android.system.OsConstants
import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.components.DeviceWriteThread
import de.tomcory.heimdall.scanner.traffic.connection.inetLayer.IpPacketBuilder
import org.pcap4j.packet.Packet
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
import java.util.Arrays

/**
 * Represents a transport-layer connection using UDP.
 *
 * @param componentManager
 * @param deviceWriter
 * @param initialPacket UDP datagram from which the necessary metadata is extracted to create the instance (ideally the very first datagram of a new socket).
 * @param ipPacketBuilder
 */
class UdpConnection internal constructor(
    componentManager: ComponentManager,
    deviceWriter: Handler,
    initialPacket: UdpPacket,
    ipPacketBuilder: IpPacketBuilder,
    remoteHost: String?
) : TransportLayerConnection(
    deviceWriter = deviceWriter,
    componentManager = componentManager,
    localPort = initialPacket.header.srcPort,
    remotePort = initialPacket.header.dstPort,
    remoteHost = remoteHost,
    ipPacketBuilder = ipPacketBuilder
) {
    override val protocol = "UDP"
    override val id = createDatabaseEntity()
    override val selectableChannel: DatagramChannel = openChannel(ipPacketBuilder.remoteAddress, componentManager.vpnService)
    override val selectionKey = connectChannel(componentManager.selector)
    override val appId: Int? = componentManager.appFinder.getAppId(ipPacketBuilder.localAddress, ipPacketBuilder.remoteAddress, localPort.valueAsInt(), remotePort.valueAsInt(), OsConstants.IPPROTO_UDP)
    override val appPackage: String? = componentManager.appFinder.getAppPackage(appId)

    private fun openChannel(remoteAddress: InetAddress, vpnService: VpnService?): DatagramChannel {
        // open the channel now, but connect it asynchronously for better performance
        state = TransportLayerState.CONNECTING
        val selectableChannel = DatagramChannel.open()
        vpnService?.protect(selectableChannel.socket())
        selectableChannel.configureBlocking(false)
        selectableChannel.socket().soTimeout = 0
        selectableChannel.socket().receiveBufferSize = componentManager.maxPacketSize
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
        Timber.d("%s Wrapping UDP out (%s bytes) to port %s", id, payload.size, remotePort.valueAsInt())

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
        Timber.d("%s Wrapping UDP in (%s bytes) from port %s", id, payload.size, remotePort.valueAsInt())
        val forwardPacket = ipPacketBuilder.buildPacket(buildPayload(payload))
        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_UDP, forwardPacket))
    }

    override fun unwrapOutbound(outgoingPacket: Packet) {
        Timber.d("%s Unwrapping UDP out (%s bytes)", id, outgoingPacket.payload.length())
        passOutboundToEncryptionLayer(outgoingPacket.payload)
    }

    override fun unwrapInbound() {
        Timber.d("%s Unwrapping UDP in", id)
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
                        passInboundToEncryptionLayer(rawData)
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