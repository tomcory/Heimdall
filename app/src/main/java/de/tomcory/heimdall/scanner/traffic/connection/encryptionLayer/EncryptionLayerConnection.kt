package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer

import de.tomcory.heimdall.scanner.traffic.connection.appLayer.AppLayerConnection
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.scanner.traffic.mitm.CertificateSniffingMitmManager

abstract class EncryptionLayerConnection(val id: Long, val transportLayer: TransportLayerConnection) {

    /**
     * Reference to the connection's application layer handler.
     */
    private var appLayer: AppLayerConnection? = null

    fun passOutboundToAppLayer(payload: ByteArray) {
        if(appLayer == null) {
            appLayer = AppLayerConnection.getInstance(payload, id, this)
        }
        appLayer?.unwrapOutbound(payload)
    }

    fun passInboundToAppLayer(payload: ByteArray) {
        if(appLayer == null) {
            throw java.lang.IllegalStateException("Inbound data without an application layer instance!")
        } else {
            appLayer?.unwrapInbound(payload)
        }
    }

    /**
     * Receives an outbound payload from the transport layer, processes it and passes it up to the application layer.
     */
    abstract fun unwrapOutbound(payload: ByteArray)

    /**
     * Receives an inbound payload from the transport layer, processes it and passes it up to the application layer.
     */
    abstract fun unwrapInbound(payload: ByteArray)

    /**
     * Receives an outbound payload from the application layer, processes it and passes it down to the transport layer.
     */
    abstract fun wrapOutbound(payload: ByteArray)

    /**
     * Receives an inbound payload from the application layer, processes it and passes it down to the transport layer.
     */
    abstract fun wrapInbound(payload: ByteArray)

    companion object {

        /**
         * Creates a [EncryptionLayerConnection] instance based on the protocol of the supplied payload (must be the very first transport-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         *
         * @param id
         * @param transportLayer
         * @param mitmManager The MitmManager to be applied to the connection. If a null value is passed, the connection will be treated as plain text.
         * @param rawPayload The connection's first raw transport-layer payload.
         */
        fun getInstance(id: Long, transportLayer: TransportLayerConnection, mitmManager: CertificateSniffingMitmManager?, rawPayload: ByteArray): EncryptionLayerConnection {
            if(mitmManager == null) {
                return PlaintextConnection(id, transportLayer)
            }

            return if (detectTls(rawPayload)) {
                TlsConnection(id, transportLayer, mitmManager)
            } else if(detectQuic(rawPayload)) {
                QuicConnection(id, transportLayer)
            } else {
                PlaintextConnection(id, transportLayer)
            }
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