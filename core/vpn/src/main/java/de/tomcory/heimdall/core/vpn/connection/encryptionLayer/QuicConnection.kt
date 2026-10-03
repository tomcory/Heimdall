package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.inetLayer.IcmpUnreachableBuilder
import de.tomcory.heimdall.core.vpn.quic.QuicInitialInspector
import de.tomcory.heimdall.core.vpn.quic.QuicPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.net.Inet4Address

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
     * on the thread that handles the device's packets, as is everything below that decides
     * whether to block.
     */
    private var inspector: QuicInitialInspector? = QuicInitialInspector()

    /**
     * Datagrams held back until the inspector's verdict, under the Block policy
     * (docs/vpn-mitm-audit.md PKT-52). Null when nothing is held: the policy does not apply, or
     * the verdict is in. The inspector gives up after a few datagrams, which bounds this.
     */
    private var held: MutableList<ByteArray>? =
        if (componentManager.doMitm && componentManager.quicPolicy == QuicPolicy.BLOCK) mutableListOf() else null

    /** Whether the flow is blocked: everything the client sends is dropped. */
    private var blocked = false

    /** ICMP errors sent for this flow so far; see [answerBlocked]. */
    private var icmpErrorsSent = 0

    override fun unwrapOutbound(payload: ByteArray) {
        if (blocked) {
            answerBlocked(payload)
            return
        }
        val held = this.held
        if (held == null) {
            // forwarded first: inspection must never hold up or change what the client sends
            passOutboundToAppLayer(payload)
            inspect(payload)
            return
        }

        held.add(payload)
        val verdict = inspect(payload) ?: return
        this.held = null
        if (shouldBlock(verdict)) {
            block(held)
        } else {
            held.forEach { passOutboundToAppLayer(it) }
        }
    }

    override fun unwrapOutbound(packet: Packet) {
        unwrapOutbound(packet.rawData)
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

    /**
     * Offers a datagram to the inspector.
     *
     * @return the inspector's result when this datagram made it terminal, otherwise null.
     */
    private fun inspect(datagram: ByteArray): QuicInitialInspector.Result? {
        val inspector = this.inspector ?: return null
        val result = try {
            inspector.offer(datagram)
        } catch (e: Exception) {
            // the inspector is not supposed to throw; if it does, the flow must not suffer
            QuicInitialInspector.Result.GaveUp("inspector failed: ${e.javaClass.simpleName}: ${e.message}")
        }
        when (result) {
            QuicInitialInspector.Result.Pending -> return null
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
        return result
    }

    /**
     * Whether to block the flow under the Block policy: it offers HTTP/3, and the TLS MitM would
     * intercept the same app and host, so a client that falls back to TLS over TCP is decrypted
     * (docs/vpn-mitm-audit.md PKT-52). A flow whose ClientHello could not be read is forwarded.
     */
    private fun shouldBlock(verdict: QuicInitialInspector.Result): Boolean {
        if (verdict !is QuicInitialInspector.Result.Complete) {
            return false
        }
        val offersHttp3 = verdict.clientHello.alpn.any { it == "h3" || it.startsWith("h3-") }
        return offersHttp3 && wouldIntercept(interceptionHost(verdict.clientHello.sni))
    }

    private fun block(held: List<ByteArray>) {
        blocked = true
        Timber.d("quic$id Blocking HTTP/3 to ${transportLayer.remoteHost ?: transportLayer.ipPacketBuilder.remoteAddress.hostAddress} so that the client falls back to TLS")
        if (id > 0) {
            CoroutineScope(Dispatchers.IO).launch {
                componentManager.databaseConnector.markConnectionBlocked(id)
            }
        }
        // Release the socket now. The connection stays in the cache, so that the client's
        // retransmissions still reach this layer and are dropped, instead of opening new flows.
        transportLayer.closeSoft()
        held.forEach { answerBlocked(it) }
    }

    /**
     * Answers a dropped datagram with an ICMP port unreachable error, so that the client gives
     * up on QUIC at once rather than after its handshake timeout. Only the first few are
     * answered, and only for IPv4: the VPN carries no IPv6 traffic today.
     */
    private fun answerBlocked(datagram: ByteArray) {
        if (icmpErrorsSent >= MAX_ICMP_ERRORS) {
            return
        }
        val local = transportLayer.ipPacketBuilder.localAddress as? Inet4Address ?: return
        val remote = transportLayer.ipPacketBuilder.remoteAddress as? Inet4Address ?: return
        icmpErrorsSent++
        val error = IcmpUnreachableBuilder.portUnreachable(local, transportLayer.localPort, remote, transportLayer.remotePort, datagram)
        transportLayer.deviceWriter.sendMessage(transportLayer.deviceWriter.obtainMessage(DeviceWriteThread.WRITE_ICMP, error))
    }

    companion object {
        /** How many dropped datagrams of a blocked flow are answered with an ICMP error. */
        private const val MAX_ICMP_ERRORS = 3
    }
}
