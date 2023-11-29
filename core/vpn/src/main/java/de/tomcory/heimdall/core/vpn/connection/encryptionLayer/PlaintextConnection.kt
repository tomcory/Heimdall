package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

class PlaintextConnection(
    id: Long,
    transportLayer: TransportLayerConnection,
    componentManager: ComponentManager
) : EncryptionLayerConnection(
    id,
    transportLayer,
    componentManager
) {

    init {
        if(id > 0) {
            Timber.d("plain$id Creating plaintext connection to ${transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${transportLayer.remotePort} (${transportLayer.remoteHost})")
        }
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        passOutboundToAppLayer(payload)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        passInboundToAppLayer(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        //TODO: implement
        passOutboundToAppLayer(packet)
    }

    override fun wrapOutbound(payload: ByteArray) {
        //TODO: implement
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        //TODO: implement
        transportLayer.wrapInbound(payload)
    }

}