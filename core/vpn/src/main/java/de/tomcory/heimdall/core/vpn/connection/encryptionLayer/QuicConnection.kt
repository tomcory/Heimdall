package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.quic.QuicInitialInspector
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
        if(id > 0) {
            Timber.d("quic$id Creating QUIC connection to ${transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${transportLayer.remotePort} (${transportLayer.remoteHost})")
        }
        doMitm = false
        persistSecurity(SecurityProtocol.QUIC)
    }

    override val protocol = "QUIC"

    /**
     * Reads the ClientHello from the client's Initial packets (docs/vpn-mitm-audit.md PKT-50).
     * Dropped once it has a result, so that the flow's later datagrams cost nothing. Only used
     * on the thread that handles the device's packets.
     */
    private var inspector: QuicInitialInspector? = QuicInitialInspector()

    override fun unwrapOutbound(payload: ByteArray) {
        // forwarded first: inspection must never hold up or change what the client sends
        passOutboundToAppLayer(payload)
        inspect(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        passOutboundToAppLayer(packet)
        inspect(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        passInboundToAppLayer(payload)
    }

    override fun wrapOutbound(payload: ByteArray) {
        transportLayer.wrapOutbound(payload)
    }

    override fun wrapInbound(payload: ByteArray) {
        transportLayer.wrapInbound(payload)
    }

    private fun inspect(datagram: ByteArray) {
        val inspector = this.inspector ?: return
        val result = try {
            inspector.offer(datagram)
        } catch (e: Exception) {
            // the inspector is not supposed to throw; if it does, the flow must not suffer
            QuicInitialInspector.Result.GaveUp("inspector failed: ${e.javaClass.simpleName}: ${e.message}")
        }
        when (result) {
            QuicInitialInspector.Result.Pending -> return
            is QuicInitialInspector.Result.Complete -> {
                val clientHello = result.clientHello
                // logged once per flow, not per datagram
                Timber.d("quic$id ClientHello: SNI ${clientHello.sni}, ALPN ${clientHello.alpn}, ECH ${clientHello.echOffered}, version 0x${Integer.toHexString(result.quicVersion)}")
                clientHello.sni?.let { transportLayer.refineRemoteHost(it, clientHello.echOffered) }
                persistSecurity(
                    SecurityProtocol.QUIC,
                    sni = clientHello.sni,
                    alpn = clientHello.alpn.takeIf { it.isNotEmpty() }?.joinToString(","),
                    echOffered = clientHello.echOffered
                )
            }
            is QuicInitialInspector.Result.GaveUp -> {
                Timber.d("quic$id No ClientHello: ${result.reason}")
            }
        }
        this.inspector = null
    }
}
