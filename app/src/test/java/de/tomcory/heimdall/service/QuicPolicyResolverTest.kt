package de.tomcory.heimdall.service

import de.tomcory.heimdall.MitmQuicPolicy
import de.tomcory.heimdall.Preferences
import de.tomcory.heimdall.core.datastore.PreferencesInitialValues
import de.tomcory.heimdall.core.vpn.quic.QuicPolicy
import org.junit.Assert.assertEquals
import org.junit.Test

/** docs/vpn-mitm-audit.md PKT-51: the QUIC policy preference and its per-session override. */
class QuicPolicyResolverTest {

    @Test
    fun `the preference decides while MitM is on`() {
        assertEquals(QuicPolicy.BLOCK, QuicPolicyResolver.resolve(true, MitmQuicPolicy.QUIC_BLOCK, null))
        assertEquals(QuicPolicy.PASSTHROUGH, QuicPolicyResolver.resolve(true, MitmQuicPolicy.QUIC_PASSTHROUGH, null))
    }

    @Test
    fun `without MitM QUIC is always passed through`() {
        assertEquals(QuicPolicy.PASSTHROUGH, QuicPolicyResolver.resolve(false, MitmQuicPolicy.QUIC_BLOCK, null))
        assertEquals(QuicPolicy.PASSTHROUGH, QuicPolicyResolver.resolve(false, MitmQuicPolicy.QUIC_BLOCK, "block"))
    }

    @Test
    fun `the session override replaces the preference, an unknown value does not`() {
        assertEquals(QuicPolicy.BLOCK, QuicPolicyResolver.resolve(true, MitmQuicPolicy.QUIC_PASSTHROUGH, "block"))
        assertEquals(QuicPolicy.BLOCK, QuicPolicyResolver.resolve(true, MitmQuicPolicy.QUIC_PASSTHROUGH, " BLOCK "))
        assertEquals(QuicPolicy.PASSTHROUGH, QuicPolicyResolver.resolve(true, MitmQuicPolicy.QUIC_BLOCK, "passthrough"))
        assertEquals(QuicPolicy.BLOCK, QuicPolicyResolver.resolve(true, MitmQuicPolicy.QUIC_BLOCK, "intercept"))
        assertEquals(QuicPolicy.PASSTHROUGH, QuicPolicyResolver.resolve(true, MitmQuicPolicy.UNRECOGNIZED, null))
    }

    @Test
    fun `existing installs and fresh ones default to passthrough`() {
        // an install from before the field existed has no stored value: proto3 yields the zero value
        assertEquals(MitmQuicPolicy.QUIC_PASSTHROUGH, Preferences.getDefaultInstance().mitmQuicPolicy)
        assertEquals(MitmQuicPolicy.QUIC_PASSTHROUGH, PreferencesInitialValues().mitmQuicPolicyInitial)
    }
}
