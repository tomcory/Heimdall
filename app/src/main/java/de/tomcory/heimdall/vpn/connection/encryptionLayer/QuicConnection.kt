package de.tomcory.heimdall.vpn.connection.encryptionLayer

import de.tomcory.heimdall.vpn.connection.transportLayer.TransportLayerConnection
import timber.log.Timber

class QuicConnection(id: Int, transportLayer: TransportLayerConnection) : EncryptionLayerConnection(id, transportLayer) {

    init {
        Timber.w("%s Creating QUIC connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Unwrapping QUIC out", id)
        passOutboundToAppLayer(payload)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Unwrapping QUIC in", id)
        passInboundToAppLayer(payload)
    }

    override fun wrapOutbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Wrapping QUIC out", id)
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Wrapping QUIC in", id)
        transportLayer.wrapInbound(payload)
    }
}