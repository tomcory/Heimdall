package de.tomcory.heimdall.core.vpn.mitm

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.cert.CertIOException
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import timber.log.Timber
import java.util.ArrayList

class SubjectAlternativeNameHolder {

    private val sans: MutableList<ASN1Encodable> = ArrayList()

    fun addIpAddress(ipAddress: String?) {
        ipAddress?.let { sans.add(GeneralName(GeneralName.iPAddress, ipAddress)) }
    }

    fun addDomainName(subjectAlternativeName: String?) {
        subjectAlternativeName?.let { sans.add(GeneralName(GeneralName.dNSName, subjectAlternativeName)) }
    }

    @Throws(CertIOException::class)
    fun fillInto(certGen: X509v3CertificateBuilder) {
        if (sans.isNotEmpty()) {
            val encodables = sans.toTypedArray()
            certGen.addExtension(
                Extension.subjectAlternativeName, false,
                DERSequence(encodables)
            )
        }
    }

    fun addAll(subjectAlternativeNames: Collection<List<*>>?) {
        if (subjectAlternativeNames != null) {
            for (each in subjectAlternativeNames) {
                if (isValidNameEntry(each)) {
                    val tag = each[0].toString().toInt()
                    val name = each[1].toString()
                    sans.add(GeneralName(tag, name))
                } else {
                    Timber.w("Invalid name entry ignored: %s", each)
                }
            }
        }
    }

    /**
     * Per the JDK contract for [java.security.cert.X509Certificate.getSubjectAlternativeNames],
     * only some GeneralName types are guaranteed to come back as a `String`; the rest
     * (otherName=0, x400Address=3, ediPartyName=5, registeredID=8) come back as a raw `byte[]`
     * (the ASN.1 DER encoding) instead. Forwarding one of those through
     * `GeneralName(tag, name.toString())` doesn't throw, but produces garbage like
     * `"[B@1a2b3c4d"` instead of the actual name - and since [subjectAlternativeNames] here is
     * built from the *untrusted* upstream server's own certificate (see
     * [CertificateSniffingMitmManager.createClientSSLEngineFor]), a server whose cert happens to
     * use one of those types would deterministically break fake-certificate generation for that
     * host. `directoryName` (4) is technically `String`-typed too, but isn't a SAN type this
     * class has any use for forwarding, so it's excluded here as well.
     *
     * @see GeneralName
     * @see <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.6">RFC 5280, § 4.2.1.6. Subject Alternative Name</a>
     */
    private fun isValidNameEntry(nameEntry: List<*>?): Boolean {
        if (nameEntry == null || nameEntry.size != 2) {
            return false
        }
        val tag = nameEntry[0]
        val name = nameEntry[1]

        return tag is Int && tag in STRING_TYPED_TAGS && name is String
    }

    companion object {
        /**
         * GeneralName tags whose value the JDK guarantees to return as a `String`, and that this
         * class actually has a use for forwarding: rfc822Name, dNSName, uniformResourceIdentifier,
         * iPAddress.
         */
        private val STRING_TYPED_TAGS = setOf(
            GeneralName.rfc822Name,
            GeneralName.dNSName,
            GeneralName.uniformResourceIdentifier,
            GeneralName.iPAddress
        )
    }
}