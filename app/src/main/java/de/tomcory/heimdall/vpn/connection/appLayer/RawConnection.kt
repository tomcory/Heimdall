package de.tomcory.heimdall.vpn.connection.appLayer

import de.tomcory.heimdall.vpn.connection.encryptionLayer.EncryptionLayerConnection
import timber.log.Timber

class RawConnection(id: Int, encryptionLayer: EncryptionLayerConnection) : AppLayerConnection(id, encryptionLayer) {

    init {
        //Timber.w("%s Creating raw connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Processing raw out", id)
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Processing raw in", id)
        encryptionLayer.wrapInbound(payload)
    }
}