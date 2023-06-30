package de.tomcory.heimdall.scanner.traffic.connection.transportLayer

import android.os.Handler
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.persistence.database.entity.Connection
import de.tomcory.heimdall.scanner.traffic.cache.ConnectionCache
import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.scanner.traffic.connection.inetLayer.IpPacketBuilder
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

    protected abstract val id: Long

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
    protected abstract val appId: Int?

    /**
     * Package name of the app holding the connection's local port.
     */
    protected abstract val appPackage: String?

    /**
     * Indicates the connection's state.
     */
    var state: TransportLayerState = TransportLayerState.CONNECTING
        protected set

    /**
     * Reference to the connection's encryption layer handler.
     */
    private var encryptionLayer: EncryptionLayerConnection? = null

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
            throw java.lang.IllegalStateException("Inbound data without an encryption layer instance!")
        } else {
            encryptionLayer?.unwrapInbound(payload)
        }
    }

    protected fun createDatabaseEntity(): Long {
        return if(remotePort == 53) {
            0
        } else {
            runBlocking {
                val ids = HeimdallDatabase.instance?.connectionDao?.insert(Connection(
                    protocol = protocol,
                    initialTimestamp = System.currentTimeMillis(),
                    initiatorId = appId ?: -1,
                    initiatorPkg = appPackage ?: appId.toString(),
                    localPort = localPort,
                    remoteHost = remoteHost ?: "",
                    remoteIp = ipPacketBuilder.remoteAddress.hostAddress ?: "",
                    remotePort = remotePort
                ))

                return@runBlocking ids?.first() ?: -1
            }
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

    /**
     * Closes the connection's outward-facing [SelectableChannel] and removes the connection from the [ConnectionCache]
     */
    fun closeHard() {
        closeSoft()
        ConnectionCache.removeConnection(this)
    }

    /**
     * Closes the connection's outward-facing [SelectableChannel] but doesn't remove the connection from the [ConnectionCache]
     */
    fun closeSoft() {
        state = TransportLayerState.CLOSING
        selectableChannel.close()
    }

    companion object {
        /**
         * Creates a [TransportLayerConnection] instance based on the transport protocol and IP version of the supplied packet.
         *
         * @param initialPacket [IpPacket] from which the necessary metadata is extracted to create the instance (ideally the very first packet of a new socket).
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
                        Timber.w("Resetting unknown TCP packet to ${initialPacket.header.dstAddr.hostAddress}:${tcpPacket.header.dstPort.valueAsInt()} ($hostname)")
                        deviceWriter.sendMessage(deviceWriter.obtainMessage(6, IpPacketBuilder.buildStray(initialPacket, TcpConnection.buildStrayRst(initialPacket))))
                        null
                    } else {
                        Timber.d("Creating new TcpConnection to ${initialPacket.header.dstAddr.hostAddress}:${tcpPacket.header.dstPort.valueAsInt()} ($hostname)")
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
                    Timber.d("Creating new UdpConnection to ${initialPacket.header.dstAddr.hostAddress}:${udpPacket.header.dstPort.valueAsInt()} ($hostname)")
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