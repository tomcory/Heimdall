package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

class HttpConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection
) : AppLayerConnection(
    id,
    encryptionLayer
) {

    init {
        Timber.d("%s Creating HTTP connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Processing HTTP out", id)
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        //TODO: implement
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Processing HTTP in", id)
        encryptionLayer.wrapInbound(payload)
    }
}