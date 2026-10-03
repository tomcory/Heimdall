package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.appLayer.AppLayerConnection
import de.tomcory.heimdall.core.vpn.connection.appLayer.RawConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.pcap4j.packet.Packet
import timber.log.Timber

abstract class EncryptionLayerConnection(
    val id: Long,
    val transportLayer: TransportLayerConnection,
    val componentManager: ComponentManager
) {

    /**
     * The connection's encryption protocol's name.
     */
    protected abstract val protocol: String

    /**
     * Reference to the connection's application layer handler.
     */
    private var appLayer: AppLayerConnection? = null

    /**
     * Indicates whether to perform a man-in-the-middle attack on this connection.
     */
    @Volatile
    var doMitm = componentManager.doMitm

    /**
     * Whether this connection keeps working when the client finishes sending but still expects
     * inbound data (a TCP half-close, docs/vpn-mitm-audit.md PKT-30). Read on the transport
     * layer's thread. Layers that merely forward bytes can always carry it.
     */
    open val supportsHalfClose: Boolean
        get() = true

    /**
     * Asynchronously records how this connection is secured, along with what its ClientHello
     * revealed, on the connection's database entry (docs/vpn-mitm-audit.md PKT-27). Connections
     * without a database entry (id 0, e.g. DNS) are skipped.
     *
     * @param sni The server name the client asked for, if any.
     * @param alpn The application protocols the client offered, comma-separated.
     * @param echOffered Whether the ClientHello carried an Encrypted Client Hello extension.
     */
    protected fun persistSecurity(
        securityProtocol: SecurityProtocol,
        sni: String? = null,
        alpn: String? = null,
        echOffered: Boolean = false
    ) {
        if (id > 0) {
            // Each write replaces all of these fields, so a connection's writes must land in the
            // order they were made. QUIC writes twice in quick succession (the label when the
            // flow is created, then what the ClientHello revealed), and two independent
            // coroutines did not always run in that order (docs/vpn-mitm-audit.md PKT-50).
            synchronized(securityWriteLock) {
                val previous = lastSecurityWrite
                lastSecurityWrite = CoroutineScope(Dispatchers.IO).launch {
                    previous?.join()
                    componentManager.databaseConnector.updateConnectionSecurity(id, securityProtocol, sni, alpn, echOffered)
                }
            }
        }
    }

    private val securityWriteLock = Any()

    /** The most recent write started by [persistSecurity]; the next one waits for it. Guarded by [securityWriteLock]. */
    private var lastSecurityWrite: Job? = null

    /**
     * The name under which this connection is judged for interception: the server name from the
     * ClientHello if there is one, else the name the DNS cache gave the remote address, else the
     * address itself. It is also the key of the passthrough cache.
     */
    protected fun interceptionHost(sni: String?): String {
        return sni ?: transportLayer.remoteHost ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: ""
    }

    /**
     * Whether the TLS MitM intercepts a connection of this app to [host], provided MitM is on:
     * the app and host are within the user's MitM scope (docs/vpn-mitm-audit.md PKT-24), and no
     * passthrough has been learned for them. The one place this is decided, so that the QUIC
     * block rule, which predicts what a TLS fallback will meet, cannot drift from the TLS path
     * (PKT-52).
     */
    protected fun wouldIntercept(host: String): Boolean {
        return componentManager.mitmScope.shouldIntercept(transportLayer.appPackage, host)
                && !(transportLayer.appId?.let { componentManager.tlsPassthroughCache.get(it, host) } ?: false)
    }

    /**
     * Passes an outbound payload to the application layer, creating an [AppLayerConnection] instance if necessary.
     *
     * @param payload The outbound payload to pass to the application layer.
     */
    fun passOutboundToAppLayer(payload: ByteArray) {
        if(appLayer == null) {
            appLayer = AppLayerConnection.getInstance(payload, id, this, componentManager)
        }
        appLayer?.unwrapOutbound(payload)
    }

    /**
     * Passes an outbound [Packet] to the application layer, creating an [AppLayerConnection] instance if necessary.
     *
     * @param packet The [Packet] to pass to the application layer.
     */
    fun passOutboundToAppLayer(packet: Packet) {
        if(appLayer == null) {
            appLayer = AppLayerConnection.getInstance(packet, id, this, componentManager)
        }
        appLayer?.unwrapOutbound(packet)
    }

    /**
     * Passes an inbound payload to the application layer, creating an [AppLayerConnection] instance if necessary.
     *
     * Note: Normally, the application layer should already be created by the time inbound data is received.
     * The creation of an application layer instance here is a fallback and will result in a [RawConnection] being created.
     *
     * @param payload The inbound payload to pass to the application layer.
     */
    fun passInboundToAppLayer(payload: ByteArray) {
        if(appLayer == null) {
            Timber.w("${protocol.lowercase()}$id Inbound data without an application layer instance, creating one...")
            appLayer = AppLayerConnection.getInstance(payload, id, this, componentManager, true)
        }
        appLayer?.unwrapInbound(payload)
    }

    /**
     * Receives a raw outbound payload from the transport layer, processes it and passes it up to the application layer.
     *
     * @param payload The raw outbound payload to process and forward to the application layer.
     */
    abstract fun unwrapOutbound(payload: ByteArray)

    /**
     * Receives an outbound [Packet] from the transport layer, processes its payload and passes it up to the application layer.
     *
     * @param packet The [Packet] to process and forward to the application layer.
     */
    abstract fun unwrapOutbound(packet: Packet)

    /**
     * Receives a raw inbound payload from the transport layer, processes it and passes it up to the application layer.
     *
     * @param payload The raw inbound payload to process and forward to the application layer.
     */
    abstract fun unwrapInbound(payload: ByteArray)

    /**
     * Receives an outbound payload from the application layer, processes it and passes it down to the transport layer.
     *
     * @param payload The outbound payload to process and forward to the transport layer.
     */
    abstract fun wrapOutbound(payload: ByteArray)

    /**
     * Receives an inbound payload from the application layer, processes it and passes it down to the transport layer.
     *
     * @param payload The inbound payload to process and forward to the transport layer.
     */
    abstract fun wrapInbound(payload: ByteArray)

    /**
     * Called by the transport layer when the device-side client closes or aborts the connection
     * itself (e.g. a TCP FIN or RST sent by the app), as opposed to the remote server closing it or
     * the connection being torn down due to an error. Called on the transport layer's thread before
     * the transport connection is torn down; implementations with their own confinement must hop
     * onto it. No-op by default.
     */
    open fun onClientClosed() {}

    /**
     * Called by the transport layer when the remote host has closed the connection, on the
     * transport layer's thread. The transport layer does not tell the device about the close
     * itself: it hands that step over as [deliverClose], and this layer must call it once
     * everything it was given before the close has been passed on to the device
     * (docs/vpn-mitm-audit.md PKT-36). Otherwise the close would overtake data that is still
     * being processed here, and the device would discard that data.
     *
     * The default suits layers that process inbound data synchronously: nothing is pending, so
     * the close is delivered at once. [deliverClose] is safe to call from any thread and more
     * than once.
     */
    open fun onRemoteClosed(deliverClose: () -> Unit) {
        deliverClose()
    }

    companion object {

        /**
         * Creates an [EncryptionLayerConnection] instance based on the protocol of the supplied payload (must be the very first transport-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         *
         * @param id The ID of the connection stack.
         * @param transportLayer The [TransportLayerConnection] instance underlying this connection.
         * @param componentManager The [ComponentManager] instance to use for this connection.
         * @param rawPayload The connection's first raw outbound transport-layer payload.
         */
        fun getInstance(id: Long, transportLayer: TransportLayerConnection, componentManager: ComponentManager, rawPayload: ByteArray, isInbound: Boolean = false): EncryptionLayerConnection {
            return if (isInbound) {
                PlaintextConnection(id, transportLayer, componentManager)
            } else if (detectTls(rawPayload)) {
                TlsConnection(id, transportLayer, componentManager)
            } else if(detectQuic(rawPayload)) {
                QuicConnection(id, transportLayer, componentManager)
            } else {
                PlaintextConnection(id, transportLayer, componentManager)
            }
        }

        /**
         * Creates an [EncryptionLayerConnection] instance based on the protocol of the supplied packet (must be the very first transport-layer packet of the connection).
         * You still need to call [unwrapOutbound] to actually process the packet once the instance is created.
         *
         * @param id The ID of the connection stack.
         * @param transportLayer The [TransportLayerConnection] instance underlying this connection.
         * @param componentManager The [ComponentManager] instance to use for this connection.
         * @param packet The connection's first outbound transport-layer [Packet].
         */
        fun getInstance(id: Long, transportLayer: TransportLayerConnection, componentManager: ComponentManager, packet: Packet, isInbound: Boolean = false): EncryptionLayerConnection {
            return getInstance(id, transportLayer, componentManager, packet.rawData, isInbound)
        }

        internal fun detectTls(rawPayload: ByteArray): Boolean {
            return rawPayload[0].toInt() == 0x16
                    && rawPayload.size > 5
                    && rawPayload[5].toInt() == 1
        }

        /**
         * Whether the payload is a QUIC client Initial, the only packet a QUIC client can open a
         * connection with (docs/vpn-mitm-audit.md PKT-26). Anything else, including other QUIC
         * packet types seen first because we joined a flow mid-connection, is not classified as
         * QUIC: there is nothing we could inspect or act on.
         */
        internal fun detectQuic(rawPayload: ByteArray): Boolean {
            // RFC 9000 section 14.1: a client must pad datagrams carrying an Initial to at least
            // 1200 bytes. This also rejects other UDP protocols whose first byte happens to
            // look like a long header.
            if(rawPayload.size < QUIC_MIN_INITIAL_DATAGRAM_SIZE) {
                return false
            }

            // header form (0x80) + fixed bit (0x40) identify a long-header packet
            val firstByte = rawPayload[0].toUByte().toInt()
            if((firstByte and 0xC0) != 0xC0) {
                return false
            }

            // each byte is parenthesised because shl and or have the same precedence in Kotlin
            val version = ((rawPayload[1].toInt() and 0xFF) shl 24) or
                    ((rawPayload[2].toInt() and 0xFF) shl 16) or
                    ((rawPayload[3].toInt() and 0xFF) shl 8) or
                    (rawPayload[4].toInt() and 0xFF)

            // version 0 marks a Version Negotiation packet, which only servers send
            if(version == 0) {
                return false
            }

            // the long packet type lives in bits 0x30, and QUIC v2 renumbered the types (RFC 9369
            // section 3.2). Unknown versions are assumed to use the v1 numbering, so they are
            // still recognised as QUIC even though we cannot decrypt them.
            val packetType = (firstByte and 0x30) shr 4
            val initialType = if(version == QUIC_VERSION_2) 0b01 else 0b00
            return packetType == initialType
        }

        private const val QUIC_MIN_INITIAL_DATAGRAM_SIZE = 1200
        private const val QUIC_VERSION_2 = 0x6b3343cf
    }
}