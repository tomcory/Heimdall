package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.FakeClientTlsDriver
import de.tomcory.heimdall.core.vpn.metadata.TlsPassthroughCache
import de.tomcory.heimdall.core.vpn.mitm.Authority
import de.tomcory.heimdall.core.vpn.mitm.CertificateHelper
import de.tomcory.heimdall.core.vpn.mitm.CertificateSniffingMitmManager
import de.tomcory.heimdall.core.vpn.mitm.SubjectAlternativeNameHolder
import io.mockk.every
import io.mockk.mockk
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult.HandshakeStatus

/**
 * Regression test for docs/vpn-mitm-audit.md PKT-25 (V-36): when several handshake records arrived
 * in one transport payload, the first one left the SSLEngine with delegated tasks pending. Those
 * tasks were run in a separately launched coroutine, so the following records were unwrapped
 * while tasks were still pending. The engine consumed none of their bytes, and TlsConnection then
 * dropped them ("prior coroutine is handling"), so the handshake hung.
 *
 * Uses TlsConnection's real single-threaded dispatcher on purpose: Dispatchers.Unconfined runs
 * launched coroutines immediately and would hide the race.
 */
class TlsHandshakeDelegatedTaskTest {

    private lateinit var mitmDir: File
    private lateinit var upstreamDir: File

    private val toUpstream = CopyOnWriteArrayList<ByteArray>()
    private val toDevice = CopyOnWriteArrayList<ByteArray>()

    @Before
    fun setup() {
        mitmDir = createTempDir()
        upstreamDir = createTempDir()
    }

    @After
    fun teardown() {
        mitmDir.deleteRecursively()
        upstreamDir.deleteRecursively()
    }

    @Test
    fun `server-facing handshake completes when the whole server flight arrives in one payload`() {
        val componentManager = mockk<ComponentManager>(relaxed = true)
        every { componentManager.doMitm } returns true
        every { componentManager.tlsPassthroughCache } returns TlsPassthroughCache()
        every { componentManager.mitmManager } returns
                CertificateSniffingMitmManager(Authority.getDefaultInstance(mitmDir), trustAllServers = true)

        val transportLayer = mockk<TransportLayerConnection>(relaxed = true)
        every { transportLayer.remoteHost } returns null
        every { transportLayer.remotePort } returns 443
        every { transportLayer.appId } returns 1000
        every { transportLayer.state } returns TransportLayerConnection.TransportLayerState.CONNECTED
        every { transportLayer.wrapOutbound(any()) } answers { toUpstream.add(firstArg()) }
        every { transportLayer.wrapInbound(any()) } answers { toDevice.add(firstArg()) }

        val tlsConnection = TlsConnection(0, transportLayer, componentManager)

        // the device app's ClientHello starts the server-facing handshake
        tlsConnection.unwrapOutbound(FakeClientTlsDriver("example.com", 443).wrap()!!)
        awaitCondition("expected the server-facing ClientHello") { toUpstream.isNotEmpty() }

        // the upstream server answers with its entire flight, delivered as one transport payload
        val upstream = createUpstreamServerEngine()
        val flight = serverFlight(upstream, toUpstream.removeAt(0))
        tlsConnection.unwrapInbound(flight)

        // completing the server-facing handshake starts the client-facing one, which writes the
        // forged ServerHello towards the device
        awaitCondition("server-facing handshake never completed, so the client-facing one never started") {
            toDevice.isNotEmpty()
        }
    }

    /** Server-mode engine presenting a leaf certificate for example.com from a throwaway CA. */
    private fun createUpstreamServerEngine(): SSLEngine {
        val authority = Authority.getDefaultInstance(upstreamDir)
        val caKeyStore = CertificateHelper.createRootCertificate(authority, "PKCS12")
        val caCert = caKeyStore.getCertificate(authority.alias)
        val caKey = caKeyStore.getKey(authority.alias, authority.password) as PrivateKey
        val sans = SubjectAlternativeNameHolder().apply { addDomainName("example.com") }
        val leafKeyStore = CertificateHelper.createServerCertificate("example.com", sans, authority, caCert, caKey)
        val context = CertificateHelper.newServerContext(CertificateHelper.getKeyManagers(leafKeyStore, authority))
        return context.createSSLEngine().apply {
            useClientMode = false
            beginHandshake()
        }
    }

    /** Feeds [clientHello] to [server] and returns everything it sends in reply, concatenated. */
    private fun serverFlight(server: SSLEngine, clientHello: ByteArray): ByteArray {
        val input = ByteBuffer.wrap(clientHello)
        val appSink = ByteBuffer.allocate(server.session.applicationBufferSize)
        val net = ByteBuffer.allocate(server.session.packetBufferSize)
        val flight = ByteArrayOutputStream()
        for (step in 0 until 100) {
            when (server.handshakeStatus) {
                HandshakeStatus.NEED_UNWRAP -> {
                    if (!input.hasRemaining()) break
                    appSink.clear()
                    server.unwrap(input, appSink)
                }
                HandshakeStatus.NEED_WRAP -> {
                    net.clear()
                    server.wrap(ByteBuffer.allocate(0), net)
                    net.flip()
                    flight.write(net.array(), 0, net.limit())
                }
                HandshakeStatus.NEED_TASK -> generateSequence { server.delegatedTask }.forEach { it.run() }
                else -> break
            }
        }
        return flight.toByteArray()
    }

    private fun awaitCondition(message: String, timeoutMs: Long = 10000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(20)
        }
        assertTrue(message, condition())
    }
}
