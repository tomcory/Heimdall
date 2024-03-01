package de.tomcory.heimdall.core.vpn.mitm

import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket

/**
 * MitmManager that uses the common name and subject alternative names
 * from the upstream certificate to create a dynamic certificate with it.
 */
class CertificateSniffingMitmManager(authority: Authority?) {

    private var sslEngineSource: SSLEngineSource? = try {
        if (authority != null) {
            SSLEngineSource(authority, trustAllServers = true, sendCerts = true)
        } else {
            null
        }
    } catch (e: Exception) {
        throw RootCertificateException("Error assembling SSLEngineSource with root CA", e)
    }


    fun createServerSSLEngine(peerHost: String?, peerPort: Int): SSLEngine? {
        return if(peerHost != null) sslEngineSource?.newSSLEngine(peerHost, peerPort) else createServerSSLEngine()
    }

    fun createServerSSLEngine(): SSLEngine? {
        return sslEngineSource?.newSSLEngine(true)
    }

    fun createServerSSLSocket(peerHost: String?, peerPort: Int): SSLSocket? {
        return if(peerHost != null) sslEngineSource?.newSSLSocket(peerHost, peerPort) else createServerSSLSocket()
    }

    fun createServerSSLSocket(): SSLSocket? {
        return sslEngineSource?.newSSLSocket()
    }

    /**
     * Call with serverSslEngine.getSession(). Creates an SSLEngine for the client side that
     * impersonates the remote server with a fake certificate.
     */
    fun createClientSSLEngineFor(serverSSLSession: SSLSession): SSLEngine {
        val engine = try {
            val upstreamCert = getCertificateFromSession(serverSSLSession)
            //TODO: store the upstream cert by commonName to review it later

            // A reasons to not use the common name and the alternative names
            // from upstream certificate from serverSslSession to create the
            // dynamic certificate:
            // It's not necessary. The host name is accepted by the browser.
            val commonName = getCommonName(upstreamCert)
            val san = SubjectAlternativeNameHolder()
            san.addAll(upstreamCert.subjectAlternativeNames)
            sslEngineSource!!.createCertForHost(commonName, san)
        } catch (e: Exception) {
            throw FakeCertificateException("Creation dynamic certificate failed", e)
        }

        engine.useClientMode = false

        return engine
    }

    @Throws(SSLPeerUnverifiedException::class)
    private fun getCertificateFromSession(sslSession: SSLSession): X509Certificate {
        val peerCerts = sslSession.peerCertificates
        val peerCert = peerCerts[0]
        if (peerCert is X509Certificate) {
            return peerCert
        }
        throw IllegalStateException("Required java.security.cert.X509Certificate, found: $peerCert")
    }

    private fun getCommonName(c: X509Certificate): String {
        val cnIndex = c.subjectDN.name.indexOf("CN=", ignoreCase = true)
        if (cnIndex == -1 || cnIndex + 3 >= c.subjectDN.name.length) {
            throw IllegalStateException("Missing CN in Subject DN: " + c.subjectDN)
        }
        val cnEndIndex = c.subjectDN.name.indexOf(",", cnIndex)
        return if (cnEndIndex == -1) {
            c.subjectDN.name.substring(cnIndex + 3).trim()
        } else {
            c.subjectDN.name.substring(cnIndex + 3, cnEndIndex).trim()
        }
    }

    //TODO: singleton isn't ideal here; it would be better to attach it to the VpnService lifecycle
    companion object {
        private var singleton: CertificateSniffingMitmManager? = null

        @JvmStatic
        fun createSingleton(authority: Authority): CertificateSniffingMitmManager? {
            singleton = CertificateSniffingMitmManager(authority)
            return singleton
        }

        @JvmStatic
        fun getSingleton(): CertificateSniffingMitmManager? {
            return singleton
        }
    }
}