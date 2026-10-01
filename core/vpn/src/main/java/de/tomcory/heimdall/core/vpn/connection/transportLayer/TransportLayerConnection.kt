package de.tomcory.heimdall.core.vpn.connection.transportLayer

import android.os.Handler
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
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
 * @param remoteHost Remote host's name as known when the connection is created (from the DNS cache), if any.
 * @property ipPacketBuilder The [IpPacketBuilder] instance used to construct [IpPacket]s for this connection.
 */
abstract class TransportLayerConnection protected constructor(
    val deviceWriter: Handler,
    val componentManager: ComponentManager,
    val localPort: Int,
    val remotePort: Int,
    remoteHost: String?,
    val ipPacketBuilder: IpPacketBuilder
) {

    /**
     * Remote host's name, or null if it is not known. Starts out as the name the DNS cache holds
     * for the remote address and can later be corrected by the encryption layer through
     * [refineRemoteHost]. Written on whichever thread the encryption layer runs on and read from
     * others, hence [Volatile].
     */
    @Volatile
    var remoteHost: String? = remoteHost
        private set

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
    protected abstract val protocol: Protocol

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
     * Indicates the connection's state. Read and (for TCP) written from both the
     * InboundTrafficHandler and OutboundTrafficHandler threads for the same connection (e.g. a
     * remote-initiated close and a device-initiated close can race), so this needs to be
     * [Volatile] for writes on one thread to be reliably visible to reads on the other.
     */
    @Volatile
    var state: TransportLayerState = TransportLayerState.CONNECTING
        protected set

    /**
     * Reference to the connection's encryption layer handler.
     */
    private var encryptionLayer: EncryptionLayerConnection? = null

    @Volatile
    private var isTracker = remoteHost?.let { componentManager.labelConnection(it) } ?: false

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
            Timber.w("${protocol.name.lowercase()}$id Inbound data without an encryption layer instance, creating one...")
            encryptionLayer = EncryptionLayerConnection.getInstance(id, this, componentManager, payload, true)
        }
        encryptionLayer?.unwrapInbound(payload)
    }

    /**
     * Tells the encryption layer (if one exists yet) that the device-side client closed or aborted
     * the connection itself. Transport implementations call this only on client-initiated close
     * paths, never on remote-initiated or error-driven teardown.
     */
    protected fun notifyClientClosed() {
        encryptionLayer?.onClientClosed()
    }

    protected fun createDatabaseEntity(): Long {
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
                    remoteHost = remoteHost,
                    remoteIp = ipPacketBuilder.remoteAddress.hostAddress ?: "",
                    remotePort = remotePort,
                    isTracker = isTracker
                )
            }
        }
    }

    /**
     * Corrects the connection's hostname with the server name the client itself asked for in its
     * ClientHello, re-evaluates the tracker label and persists both
     * (docs/vpn-mitm-audit.md PKT-28). The name known at creation time is only a reverse lookup
     * of the remote address in the DNS cache: it is missing when the app resolves names outside
     * our view (DoH/DoT, Private DNS, lookups made before the VPN started) and ambiguous when
     * several hosts share one address.
     *
     * @param sni The server name from the ClientHello.
     * @param echOffered Whether the ClientHello carried an Encrypted Client Hello extension. If
     * it did, [sni] may only be the ECH provider's public name rather than the real host, so it
     * fills in a missing hostname but never replaces one we already have. Clients also send the
     * extension as GREASE, where [sni] is the real host and matches the DNS-derived name anyway.
     */
    fun refineRemoteHost(sni: String, echOffered: Boolean) {
        val refined = sni.trim().lowercase().removeSuffix(".")
        val current = remoteHost
        if (refined.isEmpty() || refined == current) {
            return
        }
        if (echOffered && !current.isNullOrEmpty()) {
            return
        }

        val refinedIsTracker = componentManager.labelConnection(refined)
        remoteHost = refined
        isTracker = refinedIsTracker

        if (id > 0) {
            CoroutineScope(Dispatchers.IO).launch {
                componentManager.databaseConnector.updateConnectionHost(id, refined, refinedIsTracker)
            }
        }
    }

    protected fun deleteDatabaseEntity() {
        runBlocking {
            componentManager.databaseConnector.deleteTransportLayerConnection(id)
        }
    }

    /**
     * Records [delta] bytes sent from the device out to the remote host by asynchronously
     * updating the connection's persisted bytesOut counter.
     */
    protected fun recordBytesOut(delta: Int) {
        if (delta > 0 && id > 0) {
            CoroutineScope(Dispatchers.IO).launch {
                componentManager.databaseConnector.updateConnectionBytesOut(id, delta)
            }
        }
    }

    /**
     * Records [delta] bytes received from the remote host by asynchronously updating the
     * connection's persisted bytesIn counter.
     */
    protected fun recordBytesIn(delta: Int) {
        if (delta > 0 && id > 0) {
            CoroutineScope(Dispatchers.IO).launch {
                componentManager.databaseConnector.updateConnectionBytesIn(id, delta)
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

    abstract fun closeClientSession()

    /**
     * Closes the connection's outward-facing [SelectableChannel], performs protocol-specific steps to close the client-side session and removes the connection from the [ConnectionCache]
     *
     * @param abortClientSession Whether to additionally perform a protocol-specific abrupt teardown
     * of the client-facing session (e.g. sending a TCP RST). Pass `false` when the client-facing
     * side is already being closed gracefully through its own handshake (e.g. a FIN/FIN-ACK
     * exchange), so as not to also signal an abrupt abort for a clean close.
     */
    fun closeHard(abortClientSession: Boolean = true) {
        closeSoft(abortClientSession)
        ConnectionCache.removeConnection(this)
    }

    /**
     * Closes the connection's outward-facing [SelectableChannel] but doesn't remove the connection from the [ConnectionCache]
     *
     * @param abortClientSession Whether to additionally perform a protocol-specific abrupt teardown
     * of the client-facing session (e.g. sending a TCP RST). Pass `false` when the client-facing
     * side is already being closed gracefully through its own handshake (e.g. a FIN/FIN-ACK
     * exchange), so as not to also signal an abrupt abort for a clean close.
     * @param finalizeState Whether to leave the connection in [TransportLayerState.CLOSED] once the
     * outward-facing channel is closed. Pass `false` when the client-facing side's own closing
     * handshake is still in flight (e.g. awaiting the device's final ACK to our FIN-ACK), so the
     * connection stays [TransportLayerState.CLOSING] and whatever handles that handshake's
     * completion is the one that finalizes the state and removes the connection from the
     * [ConnectionCache].
     */
    fun closeSoft(abortClientSession: Boolean = true, finalizeState: Boolean = true) {
        Timber.d("${protocol.name.lowercase()}$id Closing transport-layer connection to ${ipPacketBuilder.remoteAddress.hostAddress}:$remotePort (${remoteHost})...")
        state = TransportLayerState.CLOSING
        try {
            selectionKey?.cancel()
            selectableChannel.close()
        } catch (e: Exception) {
            Timber.e(e, "${protocol.name.lowercase()}${id} Error closing SelectableChannel")
        }
        if (abortClientSession) {
            closeClientSession()
        }
        if (finalizeState) {
            state = TransportLayerState.CLOSED
        }
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
//                        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_STRAY, IpPacketBuilder.buildStray(initialPacket, TcpConnection.buildStrayRst(initialPacket))))
//                        null
//                    } else
                    if(tcpPacket.header.fin || tcpPacket.header.ack || tcpPacket.header.rst) {
                        val headerString = if(tcpPacket.header.fin) "FIN" else "" + if(tcpPacket.header.ack) "ACK" else "" + if (tcpPacket.header.rst) "RST" else ""
                        Timber.w("Resetting unknown TCP packet ($headerString) to ${initialPacket.header.dstAddr.hostAddress}:${tcpPacket.header.dstPort.valueAsInt()} ($hostname)")
                        deviceWriter.sendMessage(deviceWriter.obtainMessage(DeviceWriteThread.WRITE_STRAY, IpPacketBuilder.buildStray(initialPacket, TcpConnection.buildStrayRst(initialPacket))))
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