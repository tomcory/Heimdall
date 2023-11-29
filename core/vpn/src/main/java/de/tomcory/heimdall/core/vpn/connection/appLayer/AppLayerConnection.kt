package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.Packet

abstract class AppLayerConnection(
    val id: Long,
    val encryptionLayer: EncryptionLayerConnection,
    val componentManager: ComponentManager
) {

    /**
     * Receives an outbound payload from the encryption layer, processes it and passes it back down to the encryption layer by calling its wrapOutbound() method.
     */
    abstract fun unwrapOutbound(payload: ByteArray)

    abstract fun unwrapOutbound(packet: Packet)

    /**
     * Receives an inbound payload from the encryption layer, processes it and passes it back down to the encryption layer by calling its wrapInbound() method.
     */
    abstract fun unwrapInbound(payload: ByteArray)

    companion object {
        private val HTTP_KEYWORDS = arrayOf("HTTP", "GET", "POST", "CONNECT", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH")

        /**
         * Creates an [AppLayerConnection] instance based on the application protocol of the supplied payload (must be the very first application-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         * @param payload
         * @param id
         * @param encryptionLayer
         */
        fun getInstance(payload: ByteArray, id: Long, encryptionLayer: EncryptionLayerConnection, componentManager: ComponentManager): AppLayerConnection {
            return try {
                if(encryptionLayer.transportLayer.remotePort == 53) {
                    DnsConnection(id, encryptionLayer, componentManager)
                } else if(payload.size > 7 && HTTP_KEYWORDS.any { String(payload.sliceArray(0..10), Charsets.UTF_8).contains(it) }) {
                    HttpConnection(id, encryptionLayer, componentManager)
                } else {
                    RawConnection(id, encryptionLayer, componentManager)
                }
            } catch (e: Exception) {
                RawConnection(id, encryptionLayer, componentManager)
            }
        }

        /**
         * Creates an [AppLayerConnection] instance based on the application protocol of the supplied payload (must be the very first application-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         * @param packet
         * @param id
         * @param encryptionLayer
         */
        fun getInstance(packet: Packet, id: Long, encryptionLayer: EncryptionLayerConnection, componentManager: ComponentManager): AppLayerConnection {
            return try {
                if(packet is DnsPacket) {
                    DnsConnection(id, encryptionLayer, componentManager)
                } else if(packet.rawData.size > 7 && HTTP_KEYWORDS.any { String(packet.rawData.sliceArray(0..10), Charsets.UTF_8).contains(it) }) {
                    HttpConnection(id, encryptionLayer, componentManager)
                } else {
                    RawConnection(id, encryptionLayer, componentManager)
                }
            } catch (e: Exception) {
                RawConnection(id, encryptionLayer, componentManager)
            }
        }
    }
}