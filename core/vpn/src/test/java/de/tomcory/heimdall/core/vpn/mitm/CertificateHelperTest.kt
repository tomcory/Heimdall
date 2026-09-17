package de.tomcory.heimdall.core.vpn.mitm

import org.junit.Assert.*
import org.junit.Test
import java.security.cert.X509Certificate
import java.security.interfaces.RSAKey
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class CertificateHelperTest {

    // Access CertificateHelper to trigger its init{} block (registers BouncyCastle)
    private val helper = CertificateHelper

    private val trustAllManagers = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    })

    @Test
    fun `createRootCertificate produces a valid CA KeyStore`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val keyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")

        assertNotNull(keyStore)
        val cert = keyStore.getCertificate(authority.alias) as X509Certificate
        assertNotNull(cert)
        assertTrue("Expected isCA = true (basicConstraints >= 0)", cert.basicConstraints >= 0)
        dir.deleteRecursively()
    }

    @Test
    fun `createRootCertificate cert is self-signed`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val keyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val cert = keyStore.getCertificate(authority.alias) as X509Certificate

        try {
            cert.verify(cert.publicKey)
        } catch (e: Exception) {
            fail("Root CA cert is not self-signed: $e")
        }
        dir.deleteRecursively()
    }

    @Test
    fun `createServerCertificate CN matches commonName argument`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias)
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as java.security.PrivateKey

        val sans = SubjectAlternativeNameHolder().apply { addDomainName("example.com") }
        val leafKeyStore = CertificateHelper.createServerCertificate("example.com", sans, authority, caCert, caKey)

        val leafCert = leafKeyStore.getCertificateChain(authority.alias)[0] as X509Certificate
        val cn = Regex("CN=([^,]+)").find(leafCert.subjectX500Principal.name)?.groupValues?.get(1)
        assertEquals("example.com", cn)
        dir.deleteRecursively()
    }

    @Test
    fun `createServerCertificate is signed by CA`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias) as X509Certificate
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as java.security.PrivateKey

        val sans = SubjectAlternativeNameHolder().apply { addDomainName("test.example.com") }
        val leafKeyStore = CertificateHelper.createServerCertificate("test.example.com", sans, authority, caCert, caKey)

        val leafCert = leafKeyStore.getCertificateChain(authority.alias)[0] as X509Certificate
        try {
            leafCert.verify(caCert.publicKey)
        } catch (e: Exception) {
            fail("Leaf cert is not signed by CA: $e")
        }
        dir.deleteRecursively()
    }

    @Test
    fun `createServerCertificate chain has length 2`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias)
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as java.security.PrivateKey

        val sans = SubjectAlternativeNameHolder().apply { addDomainName("chain.example.com") }
        val leafKeyStore = CertificateHelper.createServerCertificate("chain.example.com", sans, authority, caCert, caKey)

        val chain = leafKeyStore.getCertificateChain(authority.alias)
        assertEquals(2, chain.size)
        dir.deleteRecursively()
    }

    @Test
    fun `generateKeyPair produces RSA key pair of requested size`() {
        val kp = CertificateHelper.generateKeyPair(2048)
        assertNotNull(kp)
        assertEquals(2048, (kp.private as RSAKey).modulus.bitLength())
        assertEquals(2048, (kp.public as RSAKey).modulus.bitLength())
    }

    @Test
    fun `getKeyManagers returns non-null non-empty array`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val keyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val managers = CertificateHelper.getKeyManagers(keyStore, authority)

        assertNotNull(managers)
        assertTrue(managers.isNotEmpty())
        dir.deleteRecursively()
    }

    @Test
    fun `newClientContext returns non-null SSLContext`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias)
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as java.security.PrivateKey
        val sans = SubjectAlternativeNameHolder().apply { addDomainName("example.com") }
        val leafKeyStore = CertificateHelper.createServerCertificate("example.com", sans, authority, caCert, caKey)
        val keyManagers = CertificateHelper.getKeyManagers(leafKeyStore, authority)

        val ctx = CertificateHelper.newClientContext(keyManagers, trustAllManagers)
        assertNotNull(ctx)
        dir.deleteRecursively()
    }

    @Test
    fun `newServerContext returns non-null SSLContext`() {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias)
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as java.security.PrivateKey
        val sans = SubjectAlternativeNameHolder().apply { addDomainName("example.com") }
        val leafKeyStore = CertificateHelper.createServerCertificate("example.com", sans, authority, caCert, caKey)
        val keyManagers = CertificateHelper.getKeyManagers(leafKeyStore, authority)

        val ctx = CertificateHelper.newServerContext(keyManagers)
        assertNotNull(ctx)
        dir.deleteRecursively()
    }
}
