package de.tomcory.heimdall.vpn.connection.encryptionLayer

import de.tomcory.heimdall.vpn.connection.transportLayer.TransportLayerConnection
import timber.log.Timber

class PlaintextConnection(id: Int, transportLayer: TransportLayerConnection) : EncryptionLayerConnection(id, transportLayer) {

    init {
        //Timber.w("%s Creating plaintext connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Unwrapping plaintext out", id)
        passOutboundToAppLayer(payload)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Unwrapping plaintext in", id)
        passInboundToAppLayer(payload)
    }

    override fun wrapOutbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Wrapping plaintext out", id)
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        //TODO: implement
        //Timber.d("%s Wrapping plaintext in", id)
        transportLayer.wrapInbound(payload)
    }

}