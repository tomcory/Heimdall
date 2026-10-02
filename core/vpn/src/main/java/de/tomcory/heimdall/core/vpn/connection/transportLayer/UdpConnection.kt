package de.tomcory.heimdall.core.vpn.connection.transportLayer

import android.os.Handler
import android.system.OsConstants
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import org.pcap4j.packet.Packet
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.UnknownPacket
import org.pcap4j.packet.namednumber.UdpPort
import timber.log.Timber
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.BufferOverflowException
import java.nio.ByteBuffer
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
    localPort = initialPacket.header.srcPort.valueAsInt(),
    remotePort = initialPacket.header.dstPort.valueAsInt(),
    remoteHost = remoteHost,
    ipPacketBuilder = ipPacketBuilder
) {
    override val protocol = Protocol.UDP
    override val appId: Int?
    override val appPackage: String?
    override val id: Long
    override val selectableChannel: DatagramChannel
    override val selectionKey: SelectionKey?

    /**
     * Wall-clock time of the last actual data transfer on this connection (i.e. the last
     * [wrapOutbound]/[unwrapInbound] call that moved a non-zero number of bytes), used by
     * [sweepIdleConnections] to idle-reap UDP "connections" that never get an explicit close
     * signal of their own (unlike TCP's FIN/RST). Initialised to construction time so a brand
     * new connection isn't immediately eligible for reaping.
     */
    @Volatile
    var lastActivityAt: Long = System.currentTimeMillis()
        private set

    init {
        // these values must be initialised in this order because they each depend on the previous one
        appId = componentManager.appFinder.getAppId(ipPacketBuilder.localAddress, ipPacketBuilder.remoteAddress, localPort, remotePort, OsConstants.IPPROTO_UDP)
        appPackage = componentManager.appFinder.getAppPackage(appId)
        id = createDatabaseEntity()

        if(id > 0) {
            Timber.d("udp$id Creating UDP Connection to ${ipPacketBuilder.remoteAddress.hostAddress}:${remotePort} ($remoteHost)")
        }

        selectableChannel = try {
            openChannel(ipPacketBuilder.remoteAddress)
        } catch (e: Exception) {
            Timber.e("udp$id Error while creating UDP connection: ${e.message}")
            state = TransportLayerState.ABORTED
            deleteDatabaseEntity()
            DatagramChannel.open()
        }
        selectionKey = if(state != TransportLayerState.ABORTED) {
            try {
                connectChannel(componentManager.selector)
            } catch (e: Exception) {
                Timber.e("udp$id Error while creating UDP connection: ${e.message}")
                state = TransportLayerState.ABORTED
                deleteDatabaseEntity()
                try {
                    selectableChannel.close()
                } catch (closeException: Exception) {
                    Timber.e("udp$id Error while closing leaked DatagramChannel: ${closeException.message}")
                }
                null
            }
        } else {
            null
        }
    }

    /**
     * Opens a [DatagramChannel] and throws all exceptions that occur during the process.
     *
     * @param remoteAddress The remote address to connect to.
     *
     * @return the opened and protected [DatagramChannel]
     */
    private fun openChannel(remoteAddress: InetAddress): DatagramChannel {
        // open the channel now, but connect it asynchronously for better performance
        state = TransportLayerState.CONNECTING
        val selectableChannel = DatagramChannel.open()
        componentManager.protectDatagramSocket(selectableChannel.socket())
        selectableChannel.configureBlocking(false)
        selectableChannel.socket().soTimeout = 0
        // UDP has no flow control: datagrams that arrive while the buffer is full are dropped by
        // the kernel. A burst (QUIC, media) easily outruns the selector thread for a moment, so
        // ask for a generous buffer; the kernel caps the request at its own limit
        // (docs/vpn-mitm-audit.md PKT-34).
        selectableChannel.socket().receiveBufferSize = RECEIVE_BUFFER_SIZE
        selectableChannel.connect(InetSocketAddress(remoteAddress, remotePort))
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
                Timber.e(e, "udp$id Error registering SelectableChannel")
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
            .srcPort(UdpPort(remotePort.toShort(), ""))
            .dstPort(UdpPort(localPort.toShort(), ""))
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(UnknownPacket.newPacket(rawPayload, 0, rawPayload.size).builder)
    }

    override fun wrapOutbound(payload: ByteArray) {
        // if the application layer returned anything, write it to the connection's outward-facing channel
        if (payload.isNotEmpty()) {
            // Wrapped rather than copied into outBuffer: a datagram can be larger than that
            // buffer, up to the 64 kB that IP allows (docs/vpn-mitm-audit.md PKT-46).
            val outBuffer = ByteBuffer.wrap(payload)
            // One attempt per datagram. A datagram channel sends a datagram whole or not at
            // all, and one it has no room for is dropped, as UDP allows. Retrying in a loop
            // would hold up the thread that handles every packet from the device
            // (docs/vpn-mitm-audit.md PKT-43).
            val bytesWritten = try {
                selectableChannel.write(outBuffer)
            } catch (e: IOException) {
                Timber.e(e, "udp$id Error writing to DatagramChannel, closing connection")
                closeHard()
                0
            } catch (e: BufferOverflowException) {
                Timber.e(e, "udp$id Error writing to DatagramChannel, closing connection")
                closeHard()
                0
            }
            if (bytesWritten == 0 && state != TransportLayerState.CLOSED && state != TransportLayerState.ABORTED) {
                Timber.w("udp$id Dropping a datagram of ${payload.size} bytes that the DatagramChannel did not take")
            }
            if (bytesWritten > 0) {
                lastActivityAt = System.currentTimeMillis()
            }
            recordBytesOut(bytesWritten)
        }
    }

    override fun wrapInbound(payload: ByteArray) {
        if(state == TransportLayerState.ABORTED) {
            return
        }
        val forwardPacket = ipPacketBuilder.buildPacket(buildPayload(payload))
        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_UDP, forwardPacket))
    }

    override fun unwrapOutbound(outgoingPacket: Packet) {
        if(state == TransportLayerState.ABORTED) {
            return
        }
        outgoingPacket.payload?.let {
            passOutboundToEncryptionLayer(it)
        }
    }

    override fun unwrapInbound() {
        if(selectionKey == null) {
            Timber.e("udp$id SelectionKey is null")
            state = TransportLayerState.ABORTED
            return
        }

        if (selectionKey.isReadable) {
            var bytesRead: Int
            var totalBytesRead = 0
            do {
                try {
                    // read and forward the incoming data chunk by chunk
                    inBuffer.clear()
                    bytesRead = selectableChannel.read(inBuffer)
                    if (bytesRead > 0) {
                        if (bytesRead == inBuffer.capacity()) {
                            // a datagram channel hands over what fits and discards the rest
                            Timber.w("udp$id Inbound datagram fills the read buffer of ${inBuffer.capacity()} bytes and may have been cut off")
                        }
                        totalBytesRead += bytesRead
                        inBuffer.flip()
                        val rawData = Arrays.copyOf(inBuffer.array(), bytesRead)

                        // pass the payload to the application layer for further processing
                        passInboundToEncryptionLayer(rawData)
                    }
                } catch (e: IOException) {
                    Timber.e(e, "udp$id Error reading data from DatagramChannel")
                    bytesRead = -1
                }
            } while (bytesRead > 0) // ignore the lint warning, bytesRead can definitely be greater than 0

            if (totalBytesRead > 0) {
                lastActivityAt = System.currentTimeMillis()
            }
            recordBytesIn(totalBytesRead)

            // no need to keep DNS connections open after the first and only packet
            if (remotePort == 53) {
                try {
                    selectableChannel.close()
                } catch (e: IOException) {
                    Timber.e(e, "udp$id Error closing DatagramChannel")
                }
                bytesRead = -1
            }

            // DatagramChannel is closed, do the same for the connection
            if (bytesRead == -1) {
                selectionKey.cancel()
                closeHard()
            }
        } else {
            Timber.e("udp$id UDP connection's channel triggered an event that isn't OP_READ")
        }
    }

    override fun closeClientSession() {}

    companion object {
        /**
         * Default idle timeout after which a UDP "connection" with no activity is closed by
         * [sweepIdleConnections], matching typical NAT UDP session timeout conventions (RFC 4787
         * recommends at least 2 minutes for NATs; this picks a slightly more generous default).
         */
        const val DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000L

        /**
         * Receive buffer requested for each flow's outward-facing socket. It only bounds how
         * many datagrams may queue up between two reads; each read still takes one datagram of
         * at most maxPacketSize bytes.
         */
        const val RECEIVE_BUFFER_SIZE = 1024 * 1024

        /**
         * Closes every currently-cached [UdpConnection] that's had no [wrapOutbound]/[unwrapInbound]
         * activity for longer than [idleTimeoutMs]. Unlike TCP, UDP has no FIN/RST of its own to
         * signal "this flow is done" - without a sweep like this, every UDP flow (QUIC, WebRTC,
         * games, ...) other than the DNS special-case would stay registered - holding a
         * DatagramChannel fd and its read/write buffers - for the entire VPN session.
         *
         * @param now Injectable for testing; defaults to the real current time.
         */
        fun sweepIdleConnections(idleTimeoutMs: Long = DEFAULT_IDLE_TIMEOUT_MS, now: Long = System.currentTimeMillis()) {
            ConnectionCache.allConnections()
                .filterIsInstance<UdpConnection>()
                .filter { now - it.lastActivityAt > idleTimeoutMs }
                .forEach { connection ->
                    try {
                        Timber.d("udp${connection.id} idle-reaping UDP connection to ${connection.remoteHost ?: connection.ipPacketBuilder.remoteAddress.hostAddress}:${connection.remotePort} (no activity for over ${idleTimeoutMs}ms)")
                        connection.closeHard()
                    } catch (e: Throwable) {
                        Timber.e(e, "Error closing idle UDP connection during sweep")
                    }
                }
        }
    }
}