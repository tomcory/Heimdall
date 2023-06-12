package de.tomcory.heimdall.scanner.traffic.mitm

import java.lang.IllegalStateException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class MergeTrustManager(trustStore: KeyStore?) : X509TrustManager {
    private val addedTm: X509TrustManager
    private val javaTm: X509TrustManager

    init {
        requireNotNull(trustStore) { "Missed trust store" }
        javaTm = defaultTrustManager(null)
        addedTm = defaultTrustManager(trustStore)
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        val issuers: MutableList<X509Certificate> = ArrayList()
        issuers.addAll(Arrays.asList(*addedTm.acceptedIssuers))
        issuers.addAll(Arrays.asList(*javaTm.acceptedIssuers))
        return issuers.toTypedArray()
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        try {
            addedTm.checkServerTrusted(chain, authType)
        } catch (e: CertificateException) {
            javaTm.checkServerTrusted(chain, authType)
        }
    }

    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        try {
            javaTm.checkClientTrusted(chain, authType)
        } catch (e: CertificateException) {
            addedTm.checkClientTrusted(chain, authType)
        }
    }

    @Throws(NoSuchAlgorithmException::class, KeyStoreException::class)
    private fun defaultTrustManager(trustStore: KeyStore?): X509TrustManager {
        val tma = TrustManagerFactory.getDefaultAlgorithm()
        val tmf = TrustManagerFactory.getInstance(tma)
        tmf.init(trustStore)
        val trustManagers = tmf.trustManagers
        for (each in trustManagers) {
            if (each is X509TrustManager) {
                return each
            }
        }
        throw IllegalStateException("Missed X509TrustManager in " + Arrays.toString(trustManagers))
    }
}