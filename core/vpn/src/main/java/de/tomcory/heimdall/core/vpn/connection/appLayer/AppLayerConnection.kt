package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.Packet

abstract class AppLayerConnection(
    val id: Int,
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
         * @param payload The first outbound payload of the connection.
         * @param id The ID of the connection stack.
         * @param encryptionLayer The [EncryptionLayerConnection] instance underlying this connection.
         * @param componentManager The [ComponentManager] instance to use for this connection.
         * @param isInbound Set to true if you need to create an instance based on inbound data. Created instances will be of type [RawConnection] if set to true.
         */
        fun getInstance(payload: ByteArray, id: Int, encryptionLayer: EncryptionLayerConnection, componentManager: ComponentManager, isInbound: Boolean = false): AppLayerConnection {
            return try {
                if(isInbound) {
                    RawConnection(id, encryptionLayer, componentManager)
                } else if(encryptionLayer.transportLayer.remotePort == 53) {
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
         * @param packet The first outbound packet of the connection.
         * @param id The ID of the connection stack.
         * @param encryptionLayer The [EncryptionLayerConnection] instance underlying this connection.
         * @param componentManager The [ComponentManager] instance to use for this connection.
         * @param isInbound Set to true if you need to create an instance based on inbound data. Created instances will be of type [RawConnection] if set to true.
         */
        fun getInstance(packet: Packet, id: Int, encryptionLayer: EncryptionLayerConnection, componentManager: ComponentManager, isInbound: Boolean = false): AppLayerConnection {
            return try {
                if(isInbound) {
                    RawConnection(id, encryptionLayer, componentManager)
                } else if(packet is DnsPacket) {
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