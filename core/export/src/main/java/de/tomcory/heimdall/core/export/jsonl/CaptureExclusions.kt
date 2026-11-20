package de.tomcory.heimdall.core.export.jsonl

import de.tomcory.heimdall.core.database.entity.ConnectionFacts
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.database.entity.SecurityProtocol

/**
 * The classes of traffic a capture could not observe as messages, counted per connection for an
 * export's manifest. An analysis reads them as the limits of what the export shows: a connection that
 * was passed through undecrypted, carried QUIC or DNS, or carried no HTTP request may have carried data
 * that the messages do not show.
 *
 * Classes:
 * - `blocked:<reason>`: Heimdall dropped the connection (`host_rule`, `quic_policy`)
 * - `dns`: DNS over UDP or TCP (port 53) or over TLS (port 853); answers fill Heimdall's DNS cache, but no
 *   message is recorded
 * - `quic`: QUIC that was forwarded, never decrypted
 * - `rejected:<reason>`: the app refused the interception of this connection (it rejected the forged
 *   certificate, closed during the handshake, or closed right after it without sending data); none of
 *   its data passed on this connection, and its retry is passed through
 * - `passthrough:<reason>`: TLS forwarded undecrypted although MitM was on, with the learned reason
 * - `tls_without_mitm`: TLS while MitM was off
 * - `no_request`: a connection that sent payload without an HTTP request being recorded on it: it
 *   stayed idle, carried another application protocol, or a request could not be parsed
 * - `udp`: other UDP traffic, which Heimdall forwards without decoding
 *
 * A connection that sent nothing is in no class.
 */
object CaptureExclusions {

    /** The prefix the VPN records on a connection whose interception the app refused. */
    private const val REJECTED = "REJECTED:"

    /**
     * @param mitm Whether the session decrypted TLS; null if not known (an export of several sessions),
     * in which case undecrypted TLS without a passthrough reason counts as `no_request`.
     * @return the number of connections per class, in a stable order.
     */
    fun classify(connections: List<ConnectionFacts>, mitm: Boolean?): Map<String, Int> {
        val counts = sortedMapOf<String, Int>()
        for (connection in connections) {
            val cls = classOf(connection, mitm) ?: continue
            counts[cls] = (counts[cls] ?: 0) + 1
        }
        return counts
    }

    internal fun classOf(c: ConnectionFacts, mitm: Boolean?): String? = when {
        c.blocked -> "blocked:${c.blockReason ?: "unknown"}"
        c.remotePort == 53 || c.remotePort == 853 -> "dns"
        c.securityProtocol == SecurityProtocol.QUIC -> "quic"
        c.bytesOut <= 0 -> null
        c.securityProtocol == SecurityProtocol.TLS && c.passthroughReason?.startsWith(REJECTED) == true ->
            "rejected:${c.passthroughReason.orEmpty().removePrefix(REJECTED)}"
        c.securityProtocol == SecurityProtocol.TLS && c.passthroughReason != null -> "passthrough:${c.passthroughReason}"
        c.securityProtocol == SecurityProtocol.TLS && mitm == false -> "tls_without_mitm"
        c.protocol == Protocol.UDP -> "udp"
        !c.hasRequest -> "no_request"
        else -> null
    }
}
