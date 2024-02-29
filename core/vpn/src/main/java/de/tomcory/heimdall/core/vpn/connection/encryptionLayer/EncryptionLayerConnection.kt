package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.appLayer.AppLayerConnection
import de.tomcory.heimdall.core.vpn.connection.appLayer.RawConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

abstract class EncryptionLayerConnection(
    val id: Int,
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
        fun getInstance(id: Int, transportLayer: TransportLayerConnection, componentManager: ComponentManager, rawPayload: ByteArray, isInbound: Boolean = false): EncryptionLayerConnection {
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
        fun getInstance(id: Int, transportLayer: TransportLayerConnection, componentManager: ComponentManager, packet: Packet, isInbound: Boolean = false): EncryptionLayerConnection {
            return getInstance(id, transportLayer, componentManager, packet.rawData, isInbound)
        }

        private fun detectTls(rawPayload: ByteArray): Boolean {
            return rawPayload[0].toInt() == 0x16
                    && rawPayload.size > 6
                    && rawPayload[5].toInt() == 1
        }

        private fun detectQuic(rawPayload: ByteArray): Boolean {
            if(rawPayload.isNotEmpty()) {
                val firstByte = rawPayload[0].toUByte().toInt()
                if((firstByte and 0x80) != 0 && (firstByte and 0x40) != 0 && rawPayload.size >= 5) {
                    // long header
                    val version = rawPayload[1].toUByte().toInt() shl 24 or
                            rawPayload[2].toUByte().toInt() shl 16 or
                            rawPayload[3].toUByte().toInt() shl 8 or
                            rawPayload[4].toUByte().toInt()
                    if (version == 1 || version == 0) {
                        return true
                    }
                }
            }
            return false
        }
    }
}