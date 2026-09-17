package de.tomcory.heimdall.core.vpn.mitm

import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Security
import java.util.*
import javax.security.auth.x500.X500Principal
import org.bouncycastle.jce.provider.BouncyCastleProvider

class SubjectAlternativeNameHolderTest {

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private fun buildCertWithHolder(holderConfig: SubjectAlternativeNameHolder.() -> Unit): X509v3CertificateBuilder {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val builder = JcaX509v3CertificateBuilder(
            X500Principal("CN=Test"),
            BigInteger.ONE,
            Date(System.currentTimeMillis() - 1000),
            Date(System.currentTimeMillis() + 100_000),
            X500Principal("CN=Test"),
            kp.public
        )
        val holder = SubjectAlternativeNameHolder()
        holder.holderConfig()
        holder.fillInto(builder)
        return builder
    }

    private fun signAndExtractSANs(builder: X509v3CertificateBuilder): Collection<List<*>>? {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val signer = JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(kp.private)
        val cert = builder.build(signer)
        val sanExtension = cert.getExtension(Extension.subjectAlternativeName) ?: return null
        val names = GeneralNames.getInstance(sanExtension.parsedValue)
        return names.names.map { gn ->
            listOf(gn.tagNo, gn.name.toString())
        }
    }

    @Test
    fun `addDomainName includes dNSName entry`() {
        val builder = buildCertWithHolder { addDomainName("example.com") }
        val sans = signAndExtractSANs(builder)

        assertNotNull(sans)
        assertTrue(sans!!.any { it[0] == GeneralName.dNSName && (it[1] as String).contains("example.com") })
    }

    @Test
    fun `addIpAddress includes iPAddress entry`() {
        val builder = buildCertWithHolder { addIpAddress("1.2.3.4") }
        val sans = signAndExtractSANs(builder)

        assertNotNull(sans)
        assertTrue(sans!!.any { it[0] == GeneralName.iPAddress })
    }

    @Test
    fun `fillInto with empty holder adds no SAN extension`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val builder = JcaX509v3CertificateBuilder(
            X500Principal("CN=Test"),
            BigInteger.ONE,
            Date(System.currentTimeMillis() - 1000),
            Date(System.currentTimeMillis() + 100_000),
            X500Principal("CN=Test"),
            kp.public
        )
        val holder = SubjectAlternativeNameHolder()
        holder.fillInto(builder)

        val signer = JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(kp.private)
        val cert = builder.build(signer)
        assertNull("SAN extension should be absent when no names were added",
            cert.getExtension(Extension.subjectAlternativeName))
    }

    @Test
    fun `addDomainName with null is silently ignored`() {
        val builder = buildCertWithHolder { addDomainName(null) }
        val sans = signAndExtractSANs(builder)
        // No crash, no SAN extension (or empty extension)
        assertTrue(sans == null || sans.isEmpty())
    }

    @Test
    fun `addIpAddress with null is silently ignored`() {
        val builder = buildCertWithHolder { addIpAddress(null) }
        val sans = signAndExtractSANs(builder)
        assertTrue(sans == null || sans.isEmpty())
    }

    @Test
    fun `multiple names of different types are all present`() {
        val builder = buildCertWithHolder {
            addDomainName("example.com")
            addDomainName("www.example.com")
            addIpAddress("93.184.216.34")
        }
        val sans = signAndExtractSANs(builder)

        assertNotNull(sans)
        val dnsNames = sans!!.filter { it[0] == GeneralName.dNSName }.map { it[1] as String }
        val ipNames = sans.filter { it[0] == GeneralName.iPAddress }

        assertTrue(dnsNames.any { it.contains("example.com") })
        assertTrue(dnsNames.any { it.contains("www.example.com") })
        assertTrue(ipNames.isNotEmpty())
    }
}
