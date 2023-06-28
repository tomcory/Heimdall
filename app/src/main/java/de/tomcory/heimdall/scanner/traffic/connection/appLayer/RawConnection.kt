package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

class RawConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection
) : AppLayerConnection(
    id,
    encryptionLayer
) {

    init {
        Timber.d("%s Creating raw connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Processing raw out", id)
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        //TODO: implement
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Processing raw in", id)
        encryptionLayer.wrapInbound(payload)
    }
}