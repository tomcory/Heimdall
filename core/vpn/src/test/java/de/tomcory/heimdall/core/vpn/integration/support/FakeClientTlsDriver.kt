package de.tomcory.heimdall.core.vpn.integration.support

import java.nio.ByteBuffer
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Drives a real client-mode [SSLEngine] standing in for "the app on the phone". The production
 * MITM code creates its own client-facing SSLEngine in server mode
 * ([de.tomcory.heimdall.core.vpn.connection.encryptionLayer.TlsConnection.setupClientSSLEngine])
 * with a dynamically-generated leaf certificate; this driver is the peer that completes that
 * handshake from the other side, entirely in the JVM, without any Android dependencies.
 *
 * Certificate validation is intentionally disabled (trust-all) - this harness is exercising the
 * MITM protocol machinery, not certificate trust policy (which is already covered by
 * CertificateHelperTest/SubjectAlternativeNameHolderTest).
 */
class FakeClientTlsDriver(hostname: String, port: Int) {

    val engine: SSLEngine

    private var appBufferIn = ByteBuffer.allocate(16384)
    private var netBufferIn = ByteBuffer.allocate(16921)
    private var netBufferOut = ByteBuffer.allocate(16921)

    init {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAll, null)
        engine = sslContext.createSSLEngine(hostname, port)
        engine.useClientMode = true
        engine.beginHandshake()
    }

    val handshakeStatus: SSLEngineResult.HandshakeStatus get() = engine.handshakeStatus

    fun isHandshakeFinished(): Boolean =
        engine.handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING && engine.session.cipherSuite != "SSL_NULL_WITH_NULL_NULL"

    /** Performs one wrap() step (used both during the handshake and to encrypt outbound application data). */
    fun wrap(payload: ByteArray = ByteArray(0)): ByteArray? {
        val appBuffer = ByteBuffer.wrap(payload)
        netBufferOut.clear()
        var res = engine.wrap(appBuffer, netBufferOut)
        while (res.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            netBufferOut = ByteBuffer.allocate(netBufferOut.capacity() * 2)
            res = engine.wrap(appBuffer, netBufferOut)
        }
        runDelegatedTasks()
        return if (netBufferOut.position() > 0) {
            netBufferOut.flip()
            val out = ByteArray(netBufferOut.limit())
            netBufferOut.get(out)
            out
        } else {
            null
        }
    }

    /** Feeds a raw TLS record received from the production code; returns decrypted application data, if any. */
    fun unwrap(record: ByteArray): ByteArray? {
        if (netBufferIn.capacity() < record.size) {
            netBufferIn = ByteBuffer.allocate(record.size)
        }
        netBufferIn.clear()
        netBufferIn.put(record)
        netBufferIn.flip()

        val decrypted = mutableListOf<Byte>()

        while (netBufferIn.hasRemaining()) {
            appBufferIn.clear()
            var res = engine.unwrap(netBufferIn, appBufferIn)
            while (res.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                appBufferIn = ByteBuffer.allocate(appBufferIn.capacity() * 2)
                res = engine.unwrap(netBufferIn, appBufferIn)
            }
            runDelegatedTasks()

            if (appBufferIn.position() > 0) {
                appBufferIn.flip()
                val out = ByteArray(appBufferIn.limit())
                appBufferIn.get(out)
                decrypted.addAll(out.toList())
            }

            if (res.status == SSLEngineResult.Status.BUFFER_UNDERFLOW || res.status == SSLEngineResult.Status.CLOSED) {
                break
            }
            if (res.bytesConsumed() == 0 && res.bytesProduced() == 0 && res.handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                break
            }
        }

        return if (decrypted.isNotEmpty()) decrypted.toByteArray() else null
    }

    private fun runDelegatedTasks() {
        while (engine.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            engine.delegatedTask?.run() ?: break
        }
    }
}
