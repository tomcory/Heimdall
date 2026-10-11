package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.DnsRDataA
import org.pcap4j.packet.DnsRDataAaaa
import org.pcap4j.packet.Packet
import timber.log.Timber

/** DNS over UDP: one message per datagram. DNS over a stream is [DnsStreamConnection]. */
class DnsConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager
) : AppLayerConnection(
    id,
    encryptionLayer,
    componentManager
) {

    init {
        if(id > 0) {
            Timber.d("dns$id Creating DNS connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }

    override fun unwrapOutbound(payload: ByteArray) {
        // queries are forwarded as they are; only the answers are read
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        if (!cacheAnswers(componentManager, payload)) {
            Timber.w("dns$id Could not read a DNS response of ${payload.size} bytes, passing it on")
        }
        encryptionLayer.wrapInbound(payload)
    }

    companion object {
        /**
         * Fills the DNS cache from the A and AAAA records of the DNS response [message], under the
         * name the response's first question asked for.
         *
         * @return false if [message] is not a DNS message that could be read.
         */
        fun cacheAnswers(componentManager: ComponentManager, message: ByteArray): Boolean {
            val dnsPacket = try {
                DnsPacket.newPacket(message, 0, message.size)
            } catch (e: Exception) {
                return false
            }
            val hostname = dnsPacket.header.questions.firstOrNull()?.qName?.name ?: return true

            dnsPacket.header.answers.forEach {
                val ip = when (val data = it.rData) {
                    is DnsRDataA -> data.address.hostAddress
                    is DnsRDataAaaa -> data.address.hostAddress
                    else -> null
                }
                if (!ip.isNullOrEmpty()) {
                    componentManager.dnsCache.put(ip, hostname, it.ttlAsLong)
                }
            }
            return true
        }
    }
}
