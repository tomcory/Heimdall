package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.DnsRDataA
import org.pcap4j.packet.DnsRDataAaaa
import org.pcap4j.packet.Packet
import timber.log.Timber

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
        Timber.d("%s Creating DNS connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        unwrapOutbound(DnsPacket.newPacket(payload, 0, payload.size))
    }

    override fun unwrapOutbound(packet: Packet) {
        Timber.d("%s Processing DNS out", id)

        val dnsPacket = packet as DnsPacket
        encryptionLayer.wrapOutbound(dnsPacket.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        Timber.d("%s Processing DNS in", id)

        val dnsPacket = DnsPacket.newPacket(payload, 0, payload.size)
        val hostname = dnsPacket.header.questions.first().qName.name

        dnsPacket.header.answers.forEach {
            val ip = when(it.rData) {
                is DnsRDataA -> {
                    val data = it.rData as DnsRDataA
                    data.address.hostAddress
                }

                is DnsRDataAaaa -> {
                    val data = it.rData as DnsRDataAaaa
                    data.address.hostAddress
                }

                else -> ""
            }

            if(ip.isNotEmpty()) {
                componentManager.dnsCache.put(ip, hostname, it.ttlAsLong)
            }
        }

        encryptionLayer.wrapInbound(dnsPacket.rawData)
    }
}