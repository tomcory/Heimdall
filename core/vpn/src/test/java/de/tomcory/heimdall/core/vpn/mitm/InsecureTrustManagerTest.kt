package de.tomcory.heimdall.core.vpn.mitm

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult.HandshakeStatus
import javax.net.ssl.SSLException

/**
 * Tests for docs/vpn-mitm-audit.md PKT-20: [InsecureTrustManager] replaces Netty's
 * InsecureTrustManagerFactory for the "trust all upstream certificates" mode. The handshake tests
 * run the MitM's real server-facing SSLEngine (from [CertificateSniffingMitmManager], with "HTTPS"
 * endpoint identification enabled) against an in-memory server engine presenting a certificate that
 * is both issued by an unknown CA and issued for a different hostname than the one connected to.
 */
class InsecureTrustManagerTest {

    private lateinit var mitmKeyStoreDir: File
    private lateinit var upstreamKeyStoreDir: File
    private lateinit var upstreamLeaf: X509Certificate

    @Before
    fun setup() {
        mitmKeyStoreDir = createTempDir()
        upstreamKeyStoreDir = createTempDir()
    }

    @After
    fun teardown() {
        mitmKeyStoreDir.deleteRecursively()
        upstreamKeyStoreDir.deleteRecursively()
    }

    @Test
    fun `every check overload accepts an arbitrary self-signed chain`() {
        createUpstreamServerEngine()
        val chain = arrayOf(upstreamLeaf)

        InsecureTrustManager.checkServerTrusted(chain, "RSA")
        InsecureTrustManager.checkServerTrusted(chain, "RSA", null as java.net.Socket?)
        InsecureTrustManager.checkServerTrusted(chain, "RSA", null as SSLEngine?)
        InsecureTrustManager.checkClientTrusted(chain, "RSA")
        InsecureTrustManager.checkClientTrusted(chain, "RSA", null as java.net.Socket?)
        InsecureTrustManager.checkClientTrusted(chain, "RSA", null as SSLEngine?)
        assertEquals(0, InsecureTrustManager.acceptedIssuers.size)
    }

    @Test
    fun `trust-all upstream engine completes a handshake despite unknown issuer and hostname mismatch`() {
        val manager = CertificateSniffingMitmManager(Authority.getDefaultInstance(mitmKeyStoreDir), trustAllServers = true)
        val clientEngine = manager.createServerSSLEngine("mismatch.test", 443)
        assertNotNull(clientEngine)

        runHandshake(clientEngine!!, createUpstreamServerEngine())

        assertEquals(upstreamLeaf, clientEngine.session.peerCertificates[0])
    }

    @Test
    fun `strict upstream engine rejects the same certificate`() {
        val manager = CertificateSniffingMitmManager(Authority.getDefaultInstance(mitmKeyStoreDir), trustAllServers = false)
        val clientEngine = manager.createServerSSLEngine("mismatch.test", 443)!!

        try {
            runHandshake(clientEngine, createUpstreamServerEngine())
            fail("expected the handshake to fail under strict validation (MergeTrustManager)")
        } catch (e: SSLException) {
            // expected
        }
    }

    /**
     * Builds a server-mode engine presenting a leaf certificate for "example.com", signed by a
     * freshly generated CA that neither the system nor Heimdall's own keystore trusts.
     */
    private fun createUpstreamServerEngine(): SSLEngine {
        val authority = Authority.getDefaultInstance(upstreamKeyStoreDir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias)
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as PrivateKey
        val sans = SubjectAlternativeNameHolder().apply { addDomainName("example.com") }
        val leafKeyStore = CertificateHelper.createServerCertificate("example.com", sans, authority, caCert, caKey)
        upstreamLeaf = leafKeyStore.getCertificateChain(authority.alias)[0] as X509Certificate

        val context = CertificateHelper.newServerContext(CertificateHelper.getKeyManagers(leafKeyStore, authority))
        return context.createSSLEngine().apply { useClientMode = false }
    }

    /**
     * Drives a complete handshake between two engines entirely in memory. Throws the first
     * [SSLException] either engine raises (e.g. on certificate rejection).
     */
    private fun runHandshake(client: SSLEngine, server: SSLEngine) {
        val appSize = maxOf(client.session.applicationBufferSize, server.session.applicationBufferSize)
        val netSize = maxOf(client.session.packetBufferSize, server.session.packetBufferSize)
        val clientToServer = ByteBuffer.allocate(netSize * 4)
        val serverToClient = ByteBuffer.allocate(netSize * 4)
        val emptyApp = ByteBuffer.allocate(0)
        val appSink = ByteBuffer.allocate(appSize * 2)

        client.beginHandshake()
        server.beginHandshake()

        fun step(engine: SSLEngine, outbound: ByteBuffer, inbound: ByteBuffer): Boolean {
            var progressed = false
            when (engine.handshakeStatus) {
                HandshakeStatus.NEED_WRAP -> {
                    val result = engine.wrap(emptyApp, outbound)
                    progressed = result.bytesProduced() > 0 || result.handshakeStatus != HandshakeStatus.NEED_WRAP
                }
                HandshakeStatus.NEED_UNWRAP -> {
                    inbound.flip()
                    appSink.clear()
                    val result = engine.unwrap(inbound, appSink)
                    inbound.compact()
                    progressed = result.bytesConsumed() > 0 || result.handshakeStatus != HandshakeStatus.NEED_UNWRAP
                }
                HandshakeStatus.NEED_TASK -> {
                    generateSequence { engine.delegatedTask }.forEach { it.run() }
                    progressed = true
                }
                else -> {}
            }
            return progressed
        }

        fun done(engine: SSLEngine) = engine.handshakeStatus == HandshakeStatus.NOT_HANDSHAKING ||
                engine.handshakeStatus == HandshakeStatus.FINISHED

        var idleRounds = 0
        while (!(done(client) && done(server))) {
            val clientProgressed = step(client, clientToServer, serverToClient)
            val serverProgressed = step(server, serverToClient, clientToServer)
            idleRounds = if (clientProgressed || serverProgressed) 0 else idleRounds + 1
            if (idleRounds > 10) {
                fail("handshake stalled: client=${client.handshakeStatus}, server=${server.handshakeStatus}")
            }
        }
    }
}
