package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import timber.log.Timber

class HttpConnection(id: Long, encryptionLayer: EncryptionLayerConnection) : AppLayerConnection(id, encryptionLayer) {

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