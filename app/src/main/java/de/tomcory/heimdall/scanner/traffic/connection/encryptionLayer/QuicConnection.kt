package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

class QuicConnection(
    id: Long,
    transportLayer: TransportLayerConnection,
    componentManager: ComponentManager
) : EncryptionLayerConnection(
    id,
    transportLayer,
    componentManager
) {

    init {
        Timber.d("%s Creating QUIC connection", id)
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        Timber.d("%s Unwrapping QUIC out", id)
        passOutboundToAppLayer(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        passOutboundToAppLayer(packet)
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