package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.PlaintextConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.TlsConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.UdpConnection
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
         * Whether the connection carries DNS that Heimdall can read: UDP or TCP to port 53, or
         * DNS over TLS (port 853) that is decrypted. A passed-through DoT connection hands the
         * application layer ciphertext, which is not DNS.
         */
        private fun isDns(encryptionLayer: EncryptionLayerConnection): Boolean {
            return when (encryptionLayer.transportLayer.remotePort) {
                53 -> encryptionLayer is PlaintextConnection
                853 -> encryptionLayer is TlsConnection && encryptionLayer.doMitm
                else -> false
            }
        }

        /**
         * The DNS connection for a connection that [isDns]: one message per datagram over UDP,
         * length-prefixed messages over a stream. TCP to port 53 used to be read like UDP, with
         * its length prefix taken for part of the message.
         */
        private fun dnsConnectionFor(id: Long, encryptionLayer: EncryptionLayerConnection, componentManager: ComponentManager): AppLayerConnection {
            return if (encryptionLayer.transportLayer is UdpConnection) {
                DnsConnection(id, encryptionLayer, componentManager)
            } else {
                DnsStreamConnection(id, encryptionLayer, componentManager)
            }
        }

        /**
         * Creates an [AppLayerConnection] instance based on the application protocol of the supplied payload (must be the very first application-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         * @param payload The first outbound payload of the connection.
         * @param id The ID of the connection stack.
         * @param encryptionLayer The [EncryptionLayerConnection] instance underlying this connection.
         * @param componentManager The [ComponentManager] instance to use for this connection.
         * @param isInbound Set to true if you need to create an instance based on inbound data. Created instances will be of type [RawConnection] if set to true.
         */
        fun getInstance(payload: ByteArray, id: Long, encryptionLayer: EncryptionLayerConnection, componentManager: ComponentManager, isInbound: Boolean = false): AppLayerConnection {
            return try {
                if(isInbound) {
                    RawConnection(id, encryptionLayer, componentManager)
                } else if(isDns(encryptionLayer)) {
                    dnsConnectionFor(id, encryptionLayer, componentManager)
                } else if(payload.size > 7 && HTTP_KEYWORDS.any { String(payload.sliceArray(0 until minOf(11, payload.size)), Charsets.UTF_8).contains(it) }) {
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
        fun getInstance(packet: Packet, id: Long, encryptionLayer: EncryptionLayerConnection, componentManager: ComponentManager, isInbound: Boolean = false): AppLayerConnection {
            return try {
                if(isInbound) {
                    RawConnection(id, encryptionLayer, componentManager)
                } else if(isDns(encryptionLayer) || (packet is DnsPacket && encryptionLayer.transportLayer is UdpConnection)) {
                    // pcap4j parses a UDP datagram as DNS by its port; over TCP the length prefix
                    // makes its parse wrong, so there only the port counts
                    dnsConnectionFor(id, encryptionLayer, componentManager)
                } else if(packet.rawData.size > 7 && HTTP_KEYWORDS.any { String(packet.rawData.sliceArray(0 until minOf(11, packet.rawData.size)), Charsets.UTF_8).contains(it) }) {
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