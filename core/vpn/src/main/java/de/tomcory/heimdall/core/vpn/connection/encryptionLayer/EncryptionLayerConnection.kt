package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.appLayer.AppLayerConnection
import de.tomcory.heimdall.core.vpn.connection.appLayer.RawConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
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
    var doMitm = componentManager.doMitm

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