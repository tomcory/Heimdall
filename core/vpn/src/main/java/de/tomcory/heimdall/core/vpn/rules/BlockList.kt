package de.tomcory.heimdall.core.vpn.rules

/**
 * The hosts whose connections the VPN drops instead of forwarding: the user's stored block list
 * plus the hosts a session was started with. `core:vpn` doesn't depend on the preference schema,
 * so the app module resolves both into this type.
 *
 * @param hosts Hostnames, matched as domain suffixes, and IP addresses, see [HostMatcher].
 */
class BlockList(hosts: List<String> = emptyList()) {

    private val matcher = HostMatcher(hosts)

    val isEmpty: Boolean get() = matcher.isEmpty

    /**
     * @param hostname The connection's name as far as it is known (from the DNS cache, an SNI or
     * an HTTP Host header), or null.
     * @param remoteIp The connection's remote address.
     */
    fun blocks(hostname: String?, remoteIp: String?): Boolean {
        if (matcher.isEmpty) {
            return false
        }
        return (!hostname.isNullOrEmpty() && matcher.matches(hostname)) || (!remoteIp.isNullOrEmpty() && matcher.matches(remoteIp))
    }

    companion object {
        /** Blocks nothing (the default when no block list is configured). */
        val NONE = BlockList()
    }
}

/** Why a connection was dropped, as stored in the connection's row. */
object BlockReason {
    /** The connection's host is on the [BlockList]. */
    const val HOST_RULE = "host_rule"

    /** HTTP/3 was blocked so that the client falls back to TLS, see `QuicPolicy.BLOCK`. */
    const val QUIC_POLICY = "quic_policy"
}
