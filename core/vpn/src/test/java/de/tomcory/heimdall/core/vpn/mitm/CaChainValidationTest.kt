package de.tomcory.heimdall.core.vpn.mitm

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * A forged certificate signed by a newly generated CA validates under PKIX with the CA as the
 * only trust anchor (docs/records/vpn-mitm-audit.md PKT-64: the CA's KeyUsage is critical and its
 * ExtendedKeyUsage no longer allows any purpose, so a validator must still accept the chain).
 *
 * With the environment variable `HEIMDALL_WRITE_CA_CHAIN` set to a directory, the CA and leaf are
 * also written there as `ca.pem` and `leaf.pem`, to check the same chain with Android's validator
 * on a device.
 */
class CaChainValidationTest {

    @Test
    fun `a forged leaf validates against a new CA under PKIX`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val caStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
            val ca = caStore.getCertificate(authority.alias) as X509Certificate
            val caKey = caStore.getKey(authority.alias, authority.password) as PrivateKey
            val sans = SubjectAlternativeNameHolder().apply { addDomainName("example.com") }
            val leafStore = CertificateHelper.createServerCertificate("example.com", sans, authority, ca, caKey)
            val leaf = leafStore.getCertificateChain(authority.alias)[0] as X509Certificate

            val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("heimdall-ca", ca)
            }
            val trustManager = TrustManagerFactory.getInstance("PKIX").apply { init(anchors) }
                .trustManagers.filterIsInstance<X509TrustManager>().single()

            // throws if the chain does not validate
            trustManager.checkServerTrusted(arrayOf(leaf, ca), "RSA")
            assertEquals(ca.subjectX500Principal, leaf.issuerX500Principal)

            System.getenv("HEIMDALL_WRITE_CA_CHAIN")?.let { out ->
                File(out).mkdirs()
                File(out, "ca.pem").writeText(pem(ca))
                File(out, "leaf.pem").writeText(pem(leaf))
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun pem(cert: X509Certificate): String =
        "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded) +
            "\n-----END CERTIFICATE-----\n"
}
