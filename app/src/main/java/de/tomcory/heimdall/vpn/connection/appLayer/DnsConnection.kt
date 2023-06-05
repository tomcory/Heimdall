package de.tomcory.heimdall.vpn.connection.appLayer

import de.tomcory.heimdall.vpn.connection.encryptionLayer.EncryptionLayerConnection
import timber.log.Timber

class DnsConnection(id: Int, encryptionLayer: EncryptionLayerConnection) : AppLayerConnection(id, encryptionLayer) {

    init {
        Timber.w("%s Creating DNS connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Processing DNS out", id)
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Processing DNS in", id)
        encryptionLayer.wrapInbound(payload)

        /*val rawDns = forwardPacket.payload.payload.rawData
        try {
            val dnsHeader = DnsPacket.newPacket(rawDns, 0, rawDns.size).header
            if (dnsHeader.getrCode().value().toInt() == 0) {
                val hostname = dnsHeader.questions[0].qName.toString()
                for (data in dnsHeader.answers) {
                    if (data.rData is DnsRDataA) {
                        val address = (data.rData as DnsRDataA).address.hostAddress
                        Timber.w("DNS: %s -> %s", hostname, address)
                        if (address != null) {
                            DnsCache.addHost(address, hostname)
                        }
                    } else if (data.rData is DnsRDataAaaa) {
                        val address = (data.rData as DnsRDataAaaa).address.hostAddress
                        Timber.w("DNS: %s -> %s", hostname, address)
                        if (address != null) {
                            DnsCache.addHost(address, hostname)
                        }
                    }
                }
            }
        } catch (e: IllegalRawDataException) {
            Timber.e(e, "Error parsing DNS response")
        }*/
    }
}