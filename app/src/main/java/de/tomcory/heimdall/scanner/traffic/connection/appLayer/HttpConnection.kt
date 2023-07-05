package de.tomcory.heimdall.scanner.traffic.connection.appLayer

import de.tomcory.heimdall.scanner.traffic.components.ComponentManager
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber

class HttpConnection(
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
            Timber.e("http$id Creating HTTP connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }

    override fun unwrapOutbound(payload: ByteArray) {
        //TODO: implement
        Timber.e("http$id Processing http out: ${String(payload, Charsets.UTF_8)}")
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        //TODO: implement
        Timber.e("http$id Processing http out: ${String(packet.rawData, Charsets.UTF_8)}")
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        //TODO: implement
        Timber.e("http$id Processing http in: ${String(payload, Charsets.UTF_8)}")
        encryptionLayer.wrapInbound(payload)
    }
}