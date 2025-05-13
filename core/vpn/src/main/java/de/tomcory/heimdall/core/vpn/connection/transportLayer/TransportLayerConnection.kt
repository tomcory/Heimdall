package de.tomcory.heimdall.core.vpn.connection.transportLayer

import android.os.Handler
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import kotlinx.coroutines.runBlocking
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UdpPacket
import timber.log.Timber
import java.nio.ByteBuffer
import java.nio.channels.SelectableChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector

/**
 * Base class for all transport-layer connection holders.
 * @property deviceWriter The [Handler] used to write packets to the device's TUN interface.
 * @property componentManager The [ComponentManager] instance to use for this connection.
 * @property localPort Intercepted client's port.
 * @property remotePort Remote host's port.
 * @property remoteHost Remote host's IP address.
 * @property ipPacketBuilder The [IpPacketBuilder] instance used to construct [IpPacket]s for this connection.
 */
abstract class TransportLayerConnection protected constructor(
    val deviceWriter: Handler,
    val componentManager: ComponentManager,
    val localPort: Int,
    val remotePort: Int,
    val remoteHost: String?,
    val ipPacketBuilder: IpPacketBuilder
) {

    /**
     * Possible states of a [TransportLayerConnection].
     */
    enum class TransportLayerState {
        /** The outward-facing channel not yet connected. */
        CONNECTING,

        /** The outward-facing channel connected and ready for data. */
        CONNECTED,

        /** The outward-facing channel is closing and no longer accepts data. */
        CLOSING,

        /** The outward-facing channel is fully closed. */
        CLOSED,

        /** The connection is in an error state and the outward-facing channel is closed. */
        ABORTED
    }

    /**
     * The connection's unique identifier.
     */
    protected abstract val id: Int

    /**
     * Buffer used for write operations on the connection's [SelectableChannel].
     * Using separate buffers allows for parallel read and write operations.
     */
    protected val outBuffer: ByteBuffer = ByteBuffer.allocate(componentManager.maxPacketSize)

    /**
     * Buffer used for read operations on the connection's [SelectableChannel].
     * Using separate buffers allows for parallel read and write operations.
     */
    protected val inBuffer: ByteBuffer = ByteBuffer.allocate(componentManager.maxPacketSize)

    /**
     * The connection's transport protocol's name.
     */
    protected abstract val protocol: String

    /**
     * The connection's [SelectableChannel]'s key as registered with the [Selector].
     */
    protected abstract val selectionKey: SelectionKey?

    /**
     * The connection's outward-facing channel.
     */
    protected abstract val selectableChannel: SelectableChannel

    /**
     * AID of the app holding the connection's local port.
     */
    abstract val appId: Int?

    /**
     * Package name of the app holding the connection's local port.
     */
    abstract val appPackage: String?

    /**
     * Indicates the connection's state.
     */
    var state: TransportLayerState = TransportLayerState.CONNECTING
        protected set

    /**
     * Reference to the connection's encryption layer handler.
     */
    private var encryptionLayer: EncryptionLayerConnection? = null

    private val isTracker = remoteHost?.let { componentManager.labelConnection(it) } ?: false

    protected fun passOutboundToEncryptionLayer(payload: ByteArray) {
        if(encryptionLayer == null) {
            encryptionLayer = EncryptionLayerConnection.getInstance(id, this, componentManager, payload)
        }
        encryptionLayer?.unwrapOutbound(payload)
    }

    protected fun passOutboundToEncryptionLayer(packet: Packet) {
        if(encryptionLayer == null) {
            encryptionLayer = EncryptionLayerConnection.getInstance(id, this, componentManager, packet)
        }
        encryptionLayer?.unwrapOutbound(packet)
    }

    protected fun passInboundToEncryptionLayer(payload: ByteArray) {
        if(encryptionLayer == null) {
            Timber.w("${protocol.lowercase()}$id Inbound data without an encryption layer instance, creating one...")
            encryptionLayer = EncryptionLayerConnection.getInstance(id, this, componentManager, payload, true)
        }
        encryptionLayer?.unwrapInbound(payload)
    }

    protected fun createDatabaseEntity(): Int {
        return if(remotePort == 53) {
            0
        } else {
            runBlocking {
                return@runBlocking componentManager.databaseConnector.persistTransportLayerConnection(
                    sessionId = componentManager.sessionId,
                    protocol = protocol,
                    ipVersion = ipPacketBuilder.ipVersion,
                    initialTimestamp = System.currentTimeMillis(),
                    initiatorId = appId ?: -1,
                    initiatorPkg = appPackage ?: appId.toString(),
                    localPort = localPort,
                    remoteHost = remoteHost ?: "",
                    remoteIp = ipPacketBuilder.remoteAddress.hostAddress ?: "",
                    remotePort = remotePort,
                    isTracker = isTracker
                )
            }
        }
    }

    protected fun deleteDatabaseEntity() {
        runBlocking {
            componentManager.databaseConnector.deleteTransportLayerConnection(id)
        }
    }

    /**
     * Constructs a transport-layer payload [Packet.Builder] to be used by [IpPacketBuilder.buildPacket].
     */
    abstract fun buildPayload(rawPayload: ByteArray): Packet.Builder

    abstract fun unwrapOutbound(outgoingPacket: Packet)

    abstract fun unwrapInbound()

    abstract fun wrapOutbound(payload: ByteArray)

    abstract fun wrapInbound(payload: ByteArray)

    abstract fun closeClientSession()

    /**
     * Closes the connection's outward-facing [SelectableChannel], performs protocol-specific steps to close the client-side session and removes the connection from the [ConnectionCache]
     */
    fun closeHard() {
        closeSoft()
        ConnectionCache.removeConnection(this)
    }

    /**
     * Closes the connection's outward-facing [SelectableChannel] but doesn't remove the connection from the [ConnectionCache]
     */
    fun closeSoft() {
        Timber.d("${protocol.lowercase()}$id Closing transport-layer connection to ${ipPacketBuilder.remoteAddress.hostAddress}:$remotePort (${remoteHost})...")
        state = TransportLayerState.CLOSING
        try {
            selectionKey?.cancel()
            selectableChannel.close()
        } catch (e: Exception) {
            Timber.e(e, "${protocol.lowercase()}${id} Error closing SelectableChannel")
        }
        closeClientSession()
        state = TransportLayerState.CLOSED
    }

    companion object {
        /**
         * Creates a [TransportLayerConnection] instance based on the transport protocol and IP version of the supplied packet.
         *
         * @param initialPacket [IpPacket] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
         * @param componentManager The [ComponentManager] instance to use for this connection.
         * @param deviceWriter The [Handler] used to write packets to the device's TUN interface.
         */
        fun getInstance(
            initialPacket: IpPacket,
            componentManager: ComponentManager,
            deviceWriter: Handler,)
        : TransportLayerConnection? {

            // if specified, query the connection cache for a matching connection
            ConnectionCache.findConnection(initialPacket)?.let {
                return it
            }

            val hostname = initialPacket.header.dstAddr.hostAddress?.let { componentManager.dnsCache.get(it) }

            val connection =  when (initialPacket.payload) {
                is TcpPacket -> {
                    val tcpPacket = initialPacket.payload as TcpPacket
//                    if(tcpPacket.header.dstPort.valueAsInt() == 853) {
//                        Timber.w("Resetting DoT packet to %s:%s", initialPacket.header.dstAddr.hostAddress, tcpPacket.header.dstPort.valueAsInt())
//                        deviceWriter.sendMessage(deviceWriter.obtainMessage(6, IpPacketBuilder.buildStray(initialPacket, TcpConnection.buildStrayRst(initialPacket))))
//                        null
//                    } else
                    if(tcpPacket.header.fin || tcpPacket.header.ack || tcpPacket.header.rst) {
                        val headerString = if(tcpPacket.header.fin) "FIN" else "" + if(tcpPacket.header.ack) "ACK" else "" + if (tcpPacket.header.rst) "RST" else ""
                        Timber.w("Resetting unknown TCP packet ($headerString) to ${initialPacket.header.dstAddr.hostAddress}:${tcpPacket.header.dstPort.valueAsInt()} ($hostname)")
                        deviceWriter.sendMessage(deviceWriter.obtainMessage(6, IpPacketBuilder.buildStray(initialPacket, TcpConnection.buildStrayRst(initialPacket))))
                        null
                    } else {
                        TcpConnection(
                            componentManager = componentManager,
                            deviceWriter = deviceWriter,
                            initialPacket = initialPacket.payload as TcpPacket,
                            ipPacketBuilder = IpPacketBuilder.getInstance(initialPacket),
                            remoteHost = hostname
                        )
                    }
                }

                is UdpPacket -> {
                    val udpPacket = initialPacket.payload as UdpPacket
                    UdpConnection(
                        componentManager = componentManager,
                        deviceWriter = deviceWriter,
                        initialPacket = udpPacket,
                        ipPacketBuilder = IpPacketBuilder.getInstance(initialPacket),
                        remoteHost = hostname
                    )
                }
                else -> {
                    Timber.e("Invalid transport protocol ${initialPacket.payload.javaClass}")
                    null
                }
            }

            if(connection != null) {
                ConnectionCache.addConnection(connection)
            }

            return connection
        }
    }
}