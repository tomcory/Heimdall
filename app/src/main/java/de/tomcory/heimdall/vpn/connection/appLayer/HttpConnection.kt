package de.tomcory.heimdall.vpn.connection.appLayer

import de.tomcory.heimdall.vpn.connection.encryptionLayer.EncryptionLayerConnection
import timber.log.Timber

class HttpConnection(id: Int, encryptionLayer: EncryptionLayerConnection) : AppLayerConnection(id, encryptionLayer) {

    init {
        Timber.w("%s Creating HTTP connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Processing HTTP out", id)
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Processing HTTP in", id)
        encryptionLayer.wrapInbound(payload)
    }
}