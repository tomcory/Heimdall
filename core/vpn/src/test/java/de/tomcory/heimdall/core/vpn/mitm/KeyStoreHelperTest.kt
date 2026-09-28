package de.tomcory.heimdall.core.vpn.mitm

import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.FileOutputStream
import java.io.FileWriter
import java.math.BigInteger
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * Regression tests for docs/vpn-mitm-audit.md PKT-09 (V-04): [KeyStoreHelper.initialiseOrLoadKeyStore]
 * used to reuse an existing keystore purely based on file *existence*, never checking whether its
 * CA certificate was actually still valid - once the CA expired, every TLS handshake would start
 * failing silently. It now checks validity before reusing, regenerating on expiry instead.
 */
class KeyStoreHelperTest {

    private val keyStoreType = "PKCS12"
    private val keyStoreExtension = ".p12"

    /**
     * Builds a self-signed CA certificate with an arbitrary validity window, bypassing
     * [CertificateHelper.createRootCertificate] (which always produces a long-lived, currently-valid
     * certificate as of PKT-08/PKT-09), then plants it on disk exactly where
     * [KeyStoreHelper.initialiseOrLoadKeyStore] expects to find an existing keystore for [authority].
     */
    private fun plantKeyStore(authority: Authority, notBefore: Date, notAfter: Date): X509Certificate {
        val keyPair = CertificateHelper.generateKeyPair(2048)
        val issuer = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, authority.issuerCN)
            .addRDN(BCStyle.O, authority.issuerO)
            .addRDN(BCStyle.OU, authority.issuerOU)
            .build()
        val serial = BigInteger.valueOf(System.nanoTime())

        val certificateBuilder = JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, issuer, keyPair.public)
        certificateBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        val signer = JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.private)
        val cert = JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer))

        val keyStore = KeyStore.getInstance(keyStoreType)
        keyStore.load(null, null)
        keyStore.setKeyEntry(authority.alias, keyPair.private as PrivateKey, authority.password, arrayOf(cert))

        FileOutputStream(authority.aliasFile(keyStoreExtension)).use { keyStore.store(it, authority.password) }
        FileWriter(authority.aliasFile(".pem")).use { writer ->
            JcaPEMWriter(writer).use { it.writeObject(cert) }
        }

        return cert
    }

    @Test
    fun `an expired keystore is regenerated rather than reused`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val expiredCert = plantKeyStore(
                authority,
                notBefore = Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(730)),
                notAfter = Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(365)) // expired a year ago
            )

            val result = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val resultCert = result.getCertificate(authority.alias) as X509Certificate

            assertNotEquals(
                "expected a fresh certificate (different serial) instead of the expired one being reused",
                expiredCert.serialNumber,
                resultCert.serialNumber
            )
            resultCert.checkValidity() // must not throw
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a not-yet-valid keystore is regenerated rather than reused`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val futureCert = plantKeyStore(
                authority,
                notBefore = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), // not valid until next year
                notAfter = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(730))
            )

            val result = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val resultCert = result.getCertificate(authority.alias) as X509Certificate

            assertNotEquals(
                "expected a fresh certificate (different serial) instead of the not-yet-valid one being reused",
                futureCert.serialNumber,
                resultCert.serialNumber
            )
            resultCert.checkValidity() // must not throw
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a currently-valid keystore is reused, not regenerated`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val validCert = plantKeyStore(
                authority,
                notBefore = Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1)),
                notAfter = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365))
            )

            val result = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val resultCert = result.getCertificate(authority.alias) as X509Certificate

            assertEquals(
                "expected the still-valid certificate to be reused as-is",
                validCert.serialNumber,
                resultCert.serialNumber
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a missing keystore is created fresh`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)

            val result = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val resultCert = result.getCertificate(authority.alias) as X509Certificate

            resultCert.checkValidity() // must not throw
            assertTrue("expected the keystore file to have been written", authority.aliasFile(keyStoreExtension).exists())
            assertTrue("expected the .pem export to have been written", authority.aliasFile(".pem").exists())
        } finally {
            dir.deleteRecursively()
        }
    }
}
