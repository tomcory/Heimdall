package de.tomcory.heimdall.core.vpn.integration.support

import de.tomcory.heimdall.core.vpn.mitm.Authority
import de.tomcory.heimdall.core.vpn.mitm.CertificateHelper
import de.tomcory.heimdall.core.vpn.mitm.SubjectAlternativeNameHolder
import java.net.InetAddress
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * Real local TLS server used as the "remote host" that the MITM's server-facing SSLEngine
 * connects to. Uses the same BouncyCastle self-signed certificate pattern already proven pure-JVM
 * in CertificateHelperTest. The production CertificateSniffingMitmManager is configured with
 * trustAllServers=true, so this server's certificate doesn't need to chain to any particular CA.
 */
class FakeTlsServer(hostname: String = "example.com", applicationProtocols: List<String> = emptyList()) {

    val leafCert: X509Certificate

    /** The ALPN protocol negotiated on the last accepted connection, "" if none (docs/records/vpn-mitm-audit.md PKT-57). */
    @Volatile
    var negotiatedProtocol: String? = null
        private set
    private val serverSocket: SSLServerSocket
    private var acceptedSocket: SSLSocket? = null
    private var thread: Thread? = null

    init {
        val dir = createTempDir()
        val authority = Authority.getDefaultInstance(dir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias)
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as PrivateKey
        val sans = SubjectAlternativeNameHolder().apply { addDomainName(hostname) }
        val leafKeyStore = CertificateHelper.createServerCertificate(hostname, sans, authority, caCert, caKey)
        leafCert = leafKeyStore.getCertificateChain(authority.alias)[0] as X509Certificate

        val keyManagers = CertificateHelper.getKeyManagers(leafKeyStore, authority)
        val sslContext = CertificateHelper.newServerContext(keyManagers)
        val factory = sslContext.serverSocketFactory
        serverSocket = factory.createServerSocket(0, 1, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        if (applicationProtocols.isNotEmpty()) {
            // the protocols this server is willing to speak; a client offering none of them is
            // rejected with no_application_protocol
            serverSocket.sslParameters = serverSocket.sslParameters.apply {
                this.applicationProtocols = applicationProtocols.toTypedArray()
            }
        }
    }

    val port: Int get() = serverSocket.localPort

    /**
     * Accepts exactly one connection on a background thread, completes the TLS handshake, then
     * invokes [handler] with the connected, already-handshaken socket.
     */
    fun acceptOnce(handler: (SSLSocket) -> Unit) {
        thread = Thread({
            println("DBG FakeTlsServer: waiting for accept on port $port")
            try {
                val socket = serverSocket.accept() as SSLSocket
                println("DBG FakeTlsServer: accepted, starting handshake")
                socket.startHandshake()
                negotiatedProtocol = socket.applicationProtocol
                println("DBG FakeTlsServer: handshake complete, cipher=${socket.session.cipherSuite}")
                acceptedSocket = socket
                handler(socket)
            } catch (e: Exception) {
                println("DBG FakeTlsServer: exception: $e")
            }
        }, "fake-tls-server").apply {
            isDaemon = true
            start()
        }
    }

    fun close() {
        try {
            acceptedSocket?.close()
        } catch (e: Exception) {
            // ignore
        }
        try {
            serverSocket.close()
        } catch (e: Exception) {
            // ignore
        }
        thread?.join(2000)
    }
}
