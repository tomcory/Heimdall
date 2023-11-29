package de.tomcory.heimdall.core.vpn.mitm

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.cert.CertIOException
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import timber.log.Timber
import java.util.ArrayList
import java.util.regex.Pattern

class SubjectAlternativeNameHolder {

    private val sans: MutableList<ASN1Encodable> = ArrayList()

    fun addIpAddress(ipAddress: String?) {
        sans.add(GeneralName(GeneralName.iPAddress, ipAddress))
    }

    fun addDomainName(subjectAlternativeName: String?) {
        sans.add(GeneralName(GeneralName.dNSName, subjectAlternativeName))
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

    private fun isValidNameEntry(nameEntry: List<*>?): Boolean {
        if (nameEntry == null || nameEntry.size != 2) {
            return false
        }
        val tag = nameEntry[0].toString()

        /*
         * @see GeneralName
         * @see <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.6">RFC 5280, § 4.2.1.6. Subject Alternative Name</a>
         */return Pattern.compile("[012345678]").matcher(tag).matches()
    }
}