package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.Packet

abstract class AppLayerConnection(
    val id: Long,
    val encryptionLayer: EncryptionLayerConnection
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
        private val HTTP_METHODS = arrayOf("GET", "POST", "CONNECT", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH")

        /**
         * Creates an [AppLayerConnection] instance based on the application protocol of the supplied payload (must be the very first application-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         * @param payload
         * @param id
         * @param encryptionLayer
         */
        fun getInstance(payload: ByteArray, id: Long, encryptionLayer: EncryptionLayerConnection): AppLayerConnection {
            //TODO: add DnsConnection
            return try {
                if(encryptionLayer.transportLayer.remotePort.valueAsInt() == 53) {
                    DnsConnection(id, encryptionLayer)
                } else if(payload.size > 7 && HTTP_METHODS.contains(payload.sliceArray(1..10).toString().substringBefore(' '))) {
                    HttpConnection(id, encryptionLayer)
                } else {
                    RawConnection(id, encryptionLayer)
                }
            } catch (e: Exception) {
                RawConnection(id, encryptionLayer)
            }
        }

        /**
         * Creates an [AppLayerConnection] instance based on the application protocol of the supplied payload (must be the very first application-layer payload of the connection).
         * You still need to call [unwrapOutbound] to actually process the payload once the instance is created.
         * @param packet
         * @param id
         * @param encryptionLayer
         */
        fun getInstance(packet: Packet, id: Long, encryptionLayer: EncryptionLayerConnection): AppLayerConnection {
            return try {
                if(packet is DnsPacket) {
                    DnsConnection(id, encryptionLayer)
                } else if(packet.rawData.size > 7 && HTTP_METHODS.contains(packet.rawData.sliceArray(1..10).toString().substringBefore(' '))) {
                    HttpConnection(id, encryptionLayer)
                } else {
                    RawConnection(id, encryptionLayer)
                }
            } catch (e: Exception) {
                RawConnection(id, encryptionLayer)
            }
        }
    }
}