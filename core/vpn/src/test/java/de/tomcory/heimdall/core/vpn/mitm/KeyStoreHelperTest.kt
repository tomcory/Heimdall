package de.tomcory.heimdall.core.vpn.mitm

import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.io.FileWriter
import java.math.BigInteger
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
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

    @Test
    fun `a keystore that can't be opened with the current password is regenerated instead of crashing`() {
        // Simulates a keystore created before per-install random passwords replaced the old
        // hardcoded literal password: the .p12 exists, but authority.password (freshly generated,
        // since there's no .pwd file yet) doesn't match what the file was actually encrypted
        // with - KeyStore.load() throws "PKCS12 key store mac invalid - wrong password or
        // corrupted file" in this situation, which used to propagate uncaught and crash VPN
        // startup entirely (docs of this fix: KeyStoreHelper.loadIfValid).
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)

            val keyPair = CertificateHelper.generateKeyPair(2048)
            val issuer = X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, authority.issuerCN)
                .addRDN(BCStyle.O, authority.issuerO)
                .addRDN(BCStyle.OU, authority.issuerOU)
                .build()
            val notBefore = Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1))
            val notAfter = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365))
            val certificateBuilder = JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(System.nanoTime()), notBefore, notAfter, issuer, keyPair.public)
            certificateBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
            val signer = JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.private)
            val cert = JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer))

            // deliberately encrypt with a DIFFERENT password than authority.password will load with
            val wrongPassword = "changeit".toCharArray()
            val keyStore = KeyStore.getInstance(keyStoreType)
            keyStore.load(null, null)
            keyStore.setKeyEntry(authority.alias, keyPair.private as PrivateKey, wrongPassword, arrayOf(cert))
            FileOutputStream(authority.aliasFile(keyStoreExtension)).use { keyStore.store(it, wrongPassword) }

            val result = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val resultCert = result.getCertificate(authority.alias) as X509Certificate

            assertNotEquals(
                "expected a fresh certificate (different serial) instead of failing to reuse the unreadable one",
                cert.serialNumber,
                resultCert.serialNumber
            )
            resultCert.checkValidity() // must not throw
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a missing pem export is re-derived from the existing keystore, not treated as a reason to regenerate`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)

            // first call creates a fresh, valid keystore + its .pem export
            val first = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val firstCert = first.getCertificate(authority.alias) as X509Certificate
            assertTrue("expected the .pem export to exist after the first call", authority.aliasFile(".pem").exists())

            // delete only the .pem export, leaving the .p12 keystore itself intact
            assertTrue("failed to delete the .pem export for the test setup", authority.aliasFile(".pem").delete())

            val second = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val secondCert = second.getCertificate(authority.alias) as X509Certificate

            assertEquals(
                "expected the same CA certificate (same serial) to be reused, not regenerated",
                firstCert.serialNumber,
                secondCert.serialNumber
            )
            assertArrayEquals(
                "expected the same CA public key to be reused",
                firstCert.publicKey.encoded,
                secondCert.publicKey.encoded
            )
            assertTrue("expected the .pem export to have been re-created", authority.aliasFile(".pem").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `subjectHashOld matches openssl x509 -subject_hash_old`() {
        // generated with `openssl req -x509 -subj "/CN=Heimdall/O=TU Berlin/OU=SNET" ...`;
        // `openssl x509 -noout -subject_hash_old` prints 49222eb4 for it
        val pem = """
            -----BEGIN CERTIFICATE-----
            MIIBxDCCAWmgAwIBAgIULwhEnhqMH51WuzNutoi5+59pMpMwCgYIKoZIzj0EAwIw
            NjERMA8GA1UEAwwISGVpbWRhbGwxEjAQBgNVBAoMCVRVIEJlcmxpbjENMAsGA1UE
            CwwEU05FVDAgFw0yNjA5MjkxOTA2MTVaGA8yMTI2MDkwNTE5MDYxNVowNjERMA8G
            A1UEAwwISGVpbWRhbGwxEjAQBgNVBAoMCVRVIEJlcmxpbjENMAsGA1UECwwEU05F
            VDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABK9E2MAK+W4OsgviQtsPQgtXiuF5
            GIQ7zy1QyElAAarCRySJ06Bc+VsRGpOGdU1fdIdIrEsk1YmnO9zl22EFhu6jUzBR
            MB0GA1UdDgQWBBSMfzo0gNORCFIFSMZXsu9LKwctrTAfBgNVHSMEGDAWgBSMfzo0
            gNORCFIFSMZXsu9LKwctrTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kA
            MEYCIQCEOk0EtSgtTgJ3b/8lZ/Je54raNspHU8RZy6ofpp4i5QIhAOKoOGlLyH29
            PG35X1qT0EqH51uOVU2QplGpG+oUpfFX
            -----END CERTIFICATE-----
        """.trimIndent()
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(pem.byteInputStream()) as X509Certificate

        assertEquals("49222eb4", KeyStoreHelper.subjectHashOld(cert))
    }

    @Test
    fun `deleteKeyStore forces a fresh CA but keeps the keystore password`() {
        val dir = createTempDir()
        try {
            val authority = Authority.getDefaultInstance(dir)
            val firstCert = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
                .getCertificate(authority.alias) as X509Certificate
            val passwordFile = File(dir, "${authority.alias}.pwd")
            val password = passwordFile.readText()

            KeyStoreHelper.deleteKeyStore(authority)

            assertFalse("expected the keystore to have been deleted", File(dir, "${authority.alias}$keyStoreExtension").exists())
            assertFalse("expected the .pem export to have been deleted", File(dir, "${authority.alias}.pem").exists())
            assertEquals("expected the keystore password to be kept", password, passwordFile.readText())

            // a fresh Authority re-reads the kept password, as a new process would
            val reloaded = Authority.getDefaultInstance(dir)
            val secondCert = KeyStoreHelper.initialiseOrLoadKeyStore(reloaded)
                .getCertificate(reloaded.alias) as X509Certificate

            assertNotEquals(
                "expected a fresh certificate after deleting the keystore",
                firstCert.serialNumber,
                secondCert.serialNumber
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `exportCaFiles writes the pem and the hash-named system file`() {
        val dir = createTempDir()
        val outDir = File(dir, "export/ca")
        try {
            val authority = Authority.getDefaultInstance(dir)
            val keyStore = KeyStoreHelper.initialiseOrLoadKeyStore(authority)
            val cert = keyStore.getCertificate(authority.alias) as X509Certificate

            val export = KeyStoreHelper.exportCaFiles(authority, keyStore, outDir)

            assertEquals(KeyStoreHelper.subjectHashOld(cert), export.hash)
            assertEquals(File(outDir, "${authority.alias}.pem"), export.pemFile)
            assertEquals(File(outDir, "${export.hash}.0"), export.systemFile)

            val factory = CertificateFactory.getInstance("X.509")
            for (file in listOf(export.pemFile, export.systemFile)) {
                val parsed = file.inputStream().use { factory.generateCertificate(it) }
                assertEquals("expected ${file.name} to contain the CA certificate", cert, parsed)
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
