package de.tomcory.heimdall.service

import de.tomcory.heimdall.MitmQuicPolicy
import de.tomcory.heimdall.core.vpn.quic.QuicPolicy

/**
 * Turns the user's QUIC policy preference into the [QuicPolicy] the VPN applies
 * (docs/vpn-mitm-audit.md PKT-51).
 */
object QuicPolicyResolver {

    /** The value of [HeimdallVpnService.QUIC_POLICY_EXTRA] that selects [QuicPolicy.BLOCK]. */
    const val OVERRIDE_BLOCK = "block"

    /** The value of [HeimdallVpnService.QUIC_POLICY_EXTRA] that selects [QuicPolicy.PASSTHROUGH]. */
    const val OVERRIDE_PASSTHROUGH = "passthrough"

    /**
     * @param doMitm Whether the session runs with MitM. Without it there is nothing a QUIC
     * client could fall back to that would be intercepted, so QUIC is always passed through.
     * @param preference The stored preference.
     * @param override The policy requested for this session only (see
     * [HeimdallVpnService.QUIC_POLICY_EXTRA]), or null. An unknown value is ignored.
     */
    fun resolve(doMitm: Boolean, preference: MitmQuicPolicy, override: String?): QuicPolicy {
        if (!doMitm) {
            return QuicPolicy.PASSTHROUGH
        }
        return when (override?.trim()?.lowercase()) {
            OVERRIDE_BLOCK -> QuicPolicy.BLOCK
            OVERRIDE_PASSTHROUGH -> QuicPolicy.PASSTHROUGH
            else -> when (preference) {
                MitmQuicPolicy.QUIC_BLOCK -> QuicPolicy.BLOCK
                // QUIC_PASSTHROUGH, and UNRECOGNIZED from a newer schema
                else -> QuicPolicy.PASSTHROUGH
            }
        }
    }
}
