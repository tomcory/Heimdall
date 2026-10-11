package de.tomcory.heimdall.core.vpn.mitm

import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession

/**
 * MitmManager that uses the common name and subject alternative names
 * from the upstream certificate to create a dynamic certificate with it.
 */
class CertificateSniffingMitmManager(authority: Authority?, trustAllServers: Boolean = false) {

    private var sslEngineSource: SSLEngineSource? = try {
        if (authority != null) {
            SSLEngineSource(authority, trustAllServers = trustAllServers, sendCerts = true)
        } else {
            null
        }
    } catch (e: Exception) {
        throw RootCertificateException("Error assembling SSLEngineSource with root CA", e)
    }


    /**
     * @param applicationProtocols What the engine offers the server through ALPN; none if empty
     * (docs/records/vpn-mitm-audit.md PKT-57).
     */
    fun createServerSSLEngine(peerHost: String?, peerPort: Int, applicationProtocols: List<String> = emptyList()): SSLEngine? {
        val engine = if(peerHost != null) sslEngineSource?.newSSLEngine(peerHost, peerPort) else createServerSSLEngine()
        engine?.let { Alpn.offer(it, applicationProtocols) }
        return engine
    }

    fun createServerSSLEngine(): SSLEngine? {
        return sslEngineSource?.newSSLEngine(true)
    }

    /**
     * Call with serverSslEngine.getSession(). Creates an SSLEngine for the client side that
     * impersonates the remote server with a fake certificate.
     *
     * @param applicationProtocols What the engine accepts from the client through ALPN; none if
     * empty (docs/records/vpn-mitm-audit.md PKT-57).
     */
    fun createClientSSLEngineFor(serverSSLSession: SSLSession, applicationProtocols: List<String> = emptyList()): SSLEngine {
        val engine = try {
            val upstreamCert = getCertificateFromSession(serverSSLSession)
            //TODO: store the upstream cert by commonName to review it later

            // The forged certificate copies the upstream certificate's common name and subject
            // alternative names, so that it is valid for every name the client may have asked
            // for, not only for the one in its SNI.
            val commonName = getCommonName(upstreamCert)
            val san = SubjectAlternativeNameHolder()
            san.addAll(upstreamCert.subjectAlternativeNames)
            sslEngineSource?.createCertForHost(commonName, san)
                ?: throw IllegalStateException("sslEngineSource is null")
        } catch (e: Exception) {
            throw FakeCertificateException("Creation dynamic certificate failed", e)
        }

        engine.useClientMode = false
        Alpn.offer(engine, applicationProtocols)

        return engine
    }

    @Throws(SSLPeerUnverifiedException::class)
    private fun getCertificateFromSession(sslSession: SSLSession): X509Certificate {
        val peerCerts = sslSession.peerCertificates
        if (peerCerts.isEmpty()) {
            throw SSLPeerUnverifiedException("No peer certificates found")
        }
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
}