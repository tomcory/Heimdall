package de.tomcory.heimdall.core.vpn.mitm

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

/**
 * Regression tests for docs/vpn-mitm-audit.md PKT-07 (V-02): [MergeTrustManager] is the trust
 * manager real upstream-server certificate validation should go through (as opposed to the
 * insecure "trust everything" trust manager this fixes). It merges a supplied trust store (here,
 * a CA the test controls) with the platform's default trust store, accepting a chain trusted by
 * either.
 */
class MergeTrustManagerTest {

    private fun buildCaAndLeaf(commonName: String): Triple<X509Certificate, PrivateKey, X509Certificate> {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
            val caCert = caKeyStore.getCertificate(authority.alias) as X509Certificate
            val caKey = caKeyStore.getKey(authority.alias, authority.password) as PrivateKey

            val sans = SubjectAlternativeNameHolder().apply { addDomainName(commonName) }
            val leafKeyStore = CertificateHelper.createServerCertificate(commonName, sans, authority, caCert, caKey)
            val leafCert = leafKeyStore.getCertificateChain(authority.alias)[0] as X509Certificate

            return Triple(caCert, caKey, leafCert)
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun trustStoreOf(alias: String, cert: X509Certificate): KeyStore {
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        trustStore.load(null, null)
        trustStore.setCertificateEntry(alias, cert)
        return trustStore
    }

    @Test
    fun `checkServerTrusted accepts a chain signed by a CA in its trust store`() {
        val (caCert, _, leafCert) = buildCaAndLeaf("trusted.example.com")
        val trustManager = MergeTrustManager(trustStoreOf("testCa", caCert))

        try {
            trustManager.checkServerTrusted(arrayOf(leafCert, caCert), "RSA")
        } catch (e: CertificateException) {
            fail("expected a cert chain signed by a CA in the trust store to be accepted, but got: $e")
        }
    }

    @Test
    fun `checkServerTrusted rejects a chain from a CA that isn't in its trust store or the system store`() {
        // trust store only contains CA A...
        val (caCertA, _, _) = buildCaAndLeaf("a.example.com")
        val trustManager = MergeTrustManager(trustStoreOf("caA", caCertA))

        // ...but the presented chain is signed by an entirely unrelated CA B, which is neither in
        // the supplied trust store nor a real publicly-trusted CA in the platform's default store
        val (caCertB, _, leafCertB) = buildCaAndLeaf("b.example.com")

        try {
            trustManager.checkServerTrusted(arrayOf(leafCertB, caCertB), "RSA")
            fail("expected a chain from an untrusted CA to be rejected")
        } catch (e: CertificateException) {
            // expected
        }
    }

    @Test
    fun `getAcceptedIssuers includes the CA from the supplied trust store`() {
        val (caCert, _, _) = buildCaAndLeaf("issuers.example.com")
        val trustManager = MergeTrustManager(trustStoreOf("testCa", caCert))

        assertTrue(
            "expected the supplied trust store's CA to be among the accepted issuers",
            trustManager.acceptedIssuers.any { it.subjectX500Principal == caCert.subjectX500Principal }
        )
    }

    @Test
    fun `constructor requires a non-null trust store`() {
        try {
            MergeTrustManager(null)
            fail("expected a null trust store to be rejected")
        } catch (e: IllegalArgumentException) {
            // expected (requireNotNull throws IllegalArgumentException)
        }
    }
}
