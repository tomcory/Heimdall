package de.tomcory.heimdall.core.vpn.mitm

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Regression test for docs/vpn-mitm-audit.md PKT-07 (V-02): the proxy's connection to the real
 * upstream server used to always trust any certificate (`trustAllServers` was hardcoded `true`),
 * so a network attacker between the phone and the real server was invisible to Heimdall. This
 * asserts the constructor's default now wires through to strict validation instead, via the same
 * `SSLEngineSource.trustAllServers` field `SSLEngineSource.initialiseSSLContext()` branches on.
 */
class CertificateSniffingMitmManagerTest {

    @Test
    fun `defaults to strict upstream certificate validation when trustAllServers is not specified`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val manager = CertificateSniffingMitmManager(authority)

            val sslEngineSourceField = CertificateSniffingMitmManager::class.java.getDeclaredField("sslEngineSource")
            sslEngineSourceField.isAccessible = true
            val sslEngineSource = sslEngineSourceField.get(manager)
            assertNotNull("expected a real SSLEngineSource to have been assembled", sslEngineSource)

            val trustAllServersField = sslEngineSource!!.javaClass.getDeclaredField("trustAllServers")
            trustAllServersField.isAccessible = true
            assertFalse(
                "expected trustAllServers to default to false (strict validation via MergeTrustManager)",
                trustAllServersField.getBoolean(sslEngineSource)
            )
        } finally {
            dir.deleteRecursively()
        }
    }
}
