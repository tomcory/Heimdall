package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

class RawConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager
) : AppLayerConnection(
    id,
    encryptionLayer,
    componentManager
) {

    init {
        if(id > 0) {
            Timber.e("raw$id Creating raw connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        if(encryptionLayer.doMitm) {
            Timber.e("raw$id Processing raw out: ${String(payload, Charsets.UTF_8)}")
        }
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        //TODO: implement
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        if(encryptionLayer.doMitm) {
            Timber.e("raw$id Processing raw in: ${String(payload, Charsets.UTF_8)}")
        }
        encryptionLayer.wrapInbound(payload)
    }
}