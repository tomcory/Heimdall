package de.tomcory.heimdall.core.vpn.quic

/**
 * What the VPN does with QUIC flows while MitM is on (docs/vpn-mitm-audit.md PKT-51). The app
 * maps the user's preference onto this, so that `core:vpn` does not depend on the preference
 * schema, as with [de.tomcory.heimdall.core.vpn.mitm.MitmScope].
 */
enum class QuicPolicy {
    /** QUIC flows are forwarded; their ClientHello is still read for the hostname. */
    PASSTHROUGH,

    /**
     * HTTP/3 flows whose TLS fallback would be intercepted are blocked, so that the client
     * falls back to TLS over TCP and its traffic can be decrypted (PKT-52).
     */
    BLOCK
}
