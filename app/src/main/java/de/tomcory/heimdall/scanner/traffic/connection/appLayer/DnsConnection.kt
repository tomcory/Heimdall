package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.Packet
import timber.log.Timber

class DnsConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection
) : AppLayerConnection(
    id,
    encryptionLayer
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
        encryptionLayer.wrapInbound(dnsPacket.rawData)
    }
}