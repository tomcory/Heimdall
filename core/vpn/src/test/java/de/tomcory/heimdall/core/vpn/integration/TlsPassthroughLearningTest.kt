package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.FakeClientTlsDriver
import de.tomcory.heimdall.core.vpn.integration.support.FakeTlsServer
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import de.tomcory.heimdall.core.vpn.metadata.TlsPassthroughCache
import de.tomcory.heimdall.core.vpn.mitm.MitmScope
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * End-to-end tests for docs/vpn-mitm-audit.md PKT-23: TlsConnection learns per-session
 * passthrough entries from client-side MitM failures, and later connections for the same
 * (app, host) pair are no longer intercepted. All connections in a test share one
 * ComponentManager, and therefore one [TlsPassthroughCache], like a real VPN session.
 */
class TlsPassthroughLearningTest {

    private lateinit var fakeTlsServer: FakeTlsServer
    private lateinit var componentManager: ComponentManager
    private lateinit var cache: TlsPassthroughCache
    private lateinit var pump: SelectorPump

    private val hostname = "example.com"
    private val appId = 1000 // ComponentManagerFixtures' default
    private val localAddr = InetAddress.getByName("10.0.0.40") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        fakeTlsServer = FakeTlsServer(hostname)
        useComponentManager()
    }

    /** (Re)builds the shared ComponentManager with the given MitM settings (PKT-24). */
    private fun useComponentManager(mitmScope: MitmScope = MitmScope.ALL, learnPassthrough: Boolean = true) {
        if (::pump.isInitialized) pump.stop()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            mitmScope = mitmScope,
            learnPassthrough = learnPassthrough
        )
        cache = componentManager.tlsPassthroughCache
        pump = SelectorPump(componentManager.selector)
        pump.start()
    }

    @After
    fun teardown() {
        pump.stop()
        fakeTlsServer.close()
        ConnectionCache.closeAllAndClear()
    }

    @Test
    fun `client rejecting the forged certificate marks the pair and the next connection passes through`() {
        // first connection: the "app" refuses Heimdall's forged certificate
        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val rejectingFlow = Flow(localPort = 45001)
        val rejectingDriver = FakeClientTlsDriver(hostname, fakeTlsServer.port, rejectingTrustManager())
        val handshakeError = runClientHandshake(rejectingFlow, rejectingDriver)
        assertNotNull("the rejecting client should have failed the handshake", handshakeError)

        awaitCondition("the pair should have been marked for passthrough") { cache.get(appId, hostname) }

        // second connection for the same pair: no MitM, so the client sees the real server's certificate
        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val passthroughFlow = Flow(localPort = 45002)
        val passthroughDriver = FakeClientTlsDriver(hostname, fakeTlsServer.port)
        assertNull("the passthrough handshake should succeed", runClientHandshake(passthroughFlow, passthroughDriver))
        assertEquals(
            "a passed-through connection must present the real upstream certificate, not a forged one",
            fakeTlsServer.leafCert,
            passthroughDriver.engine.session.peerCertificates[0]
        )
    }

    @Test
    fun `client closing during the handshake marks the pair`() {
        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val flow = Flow(localPort = 45010)
        val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port)

        flow.send(driver.wrap()!!) // ClientHello
        // the first bytes back are the client-facing handshake flight, so that handshake is now running
        assertNotNull("expected the client-facing handshake to start", flow.nextPayload())

        flow.sendFin()

        awaitCondition("the pair should have been marked for passthrough") { cache.get(appId, hostname) }
    }

    @Test
    fun `closing without data after the handshake marks the pair only on the second occurrence`() {
        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val firstFlow = Flow(localPort = 45020)
        assertNull(runClientHandshake(firstFlow, FakeClientTlsDriver(hostname, fakeTlsServer.port)))
        firstFlow.sendFin()

        awaitCondition("the first close should have been counted") { suspectCount() == 1 }
        assertFalse("one pinning-style close must not be enough", cache.get(appId, hostname))

        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val secondFlow = Flow(localPort = 45021)
        assertNull(runClientHandshake(secondFlow, FakeClientTlsDriver(hostname, fakeTlsServer.port)))
        secondFlow.sendFin()

        awaitCondition("the pair should have been marked for passthrough") { cache.get(appId, hostname) }
    }

    @Test
    fun `closing with close_notify and no data counts like a TCP close`() {
        for ((index, localPort) in listOf(45025, 45026).withIndex()) {
            fakeTlsServer.acceptOnce(::holdUntilClosed)
            val flow = Flow(localPort)
            val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port)
            assertNull(runClientHandshake(flow, driver))

            // end the TLS session with close_notify only, no TCP FIN
            driver.engine.closeOutbound()
            flow.send(driver.wrap()!!)

            if (index == 0) {
                awaitCondition("the first close_notify should have been counted") { suspectCount() == 1 }
                assertFalse(cache.get(appId, hostname))
            }
        }

        awaitCondition("the pair should have been marked for passthrough") { cache.get(appId, hostname) }
    }

    @Test
    fun `a normal request-response connection does not mark the pair`() {
        val requestReceived = AtomicReference<ByteArray?>(null)
        val response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        fakeTlsServer.acceptOnce { socket ->
            val buf = ByteArray(8192)
            val read = socket.inputStream.read(buf)
            if (read > 0) requestReceived.set(buf.copyOf(read))
            socket.outputStream.write(response.toByteArray())
            socket.outputStream.flush()
            holdUntilClosed(socket)
        }
        val flow = Flow(localPort = 45030)
        val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port)
        assertNull(runClientHandshake(flow, driver))

        flow.send(driver.wrap("GET / HTTP/1.1\r\nHost: $hostname\r\n\r\n".toByteArray())!!)
        awaitCondition("the request should reach the server") { requestReceived.get() != null }
        var decrypted: ByteArray? = null
        val deadline = System.currentTimeMillis() + 10000
        while (decrypted == null && System.currentTimeMillis() < deadline) {
            flow.nextPayload(timeoutMs = 200)?.let { decrypted = driver.unwrap(it) }
        }
        assertEquals(response, decrypted?.let { String(it) })

        flow.sendFin()

        // negative assertion: give the connection's scope time to process the close, then check
        // that nothing was recorded (a positive signal would have landed well within this window)
        Thread.sleep(500)
        assertFalse(cache.get(appId, hostname))
        assertEquals(0, suspectCount())
    }

    // ---- MitM scope and learning switch (docs/vpn-mitm-audit.md PKT-24) ----

    @Test
    fun `host outside the MitM scope is passed through`() {
        useComponentManager(mitmScope = MitmScope(hostMode = MitmScope.HostMode.BLACKLIST, hosts = listOf(hostname)))
        assertPassedThrough(localPort = 45040)
    }

    @Test
    fun `app outside the MitM scope is passed through`() {
        // the fixture attributes every connection to "com.example.test"
        useComponentManager(mitmScope = MitmScope(includedApps = setOf("com.other.app")))
        assertPassedThrough(localPort = 45041)
    }

    @Test
    fun `app and host inside the MitM scope are still intercepted`() {
        useComponentManager(mitmScope = MitmScope(
            includedApps = setOf("com.example.test"),
            hostMode = MitmScope.HostMode.WHITELIST,
            hosts = listOf(hostname)
        ))
        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port)
        assertNull(runClientHandshake(Flow(localPort = 45042), driver))
        assertNotEquals(
            "an intercepted connection must present a forged certificate",
            fakeTlsServer.leafCert,
            driver.engine.session.peerCertificates[0]
        )
    }

    @Test
    fun `nothing is learned when passthrough learning is switched off`() {
        useComponentManager(learnPassthrough = false)
        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val flow = Flow(localPort = 45043)
        val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port, rejectingTrustManager())
        assertNotNull(runClientHandshake(flow, driver))

        // negative assertion: allow time for the rejection to be processed (see the normal-flow test)
        Thread.sleep(500)
        assertFalse(cache.get(appId, hostname))
    }

    /** Opens a connection and asserts the client sees the real upstream certificate, i.e. no MitM. */
    private fun assertPassedThrough(localPort: Int) {
        fakeTlsServer.acceptOnce(::holdUntilClosed)
        val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port)
        assertNull("the passthrough handshake should succeed", runClientHandshake(Flow(localPort), driver))
        assertEquals(fakeTlsServer.leafCert, driver.engine.session.peerCertificates[0])
    }

    // ---- helpers ----

    /** One device-side TCP flow to [fakeTlsServer], with the local TCP handshake already completed. */
    private inner class Flow(private val localPort: Int) {
        private val deviceWriter = RecordingDeviceWriter()
        private val connection: TransportLayerConnection
        private var nextMessageIndex: Int
        private var deviceSeq = 1

        init {
            val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, fakeTlsServer.port)
            connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
            connection.unwrapOutbound(synPacket.payload)
            awaitCondition("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
            connection.unwrapOutbound(
                PacketFixtures.buildTcpDataPacket(localAddr, localPort, remoteAddr, fakeTlsServer.port, seq = 1, ack = 1, pshFlag = false).payload
            )
            nextMessageIndex = deviceWriter.sentMessages.size
        }

        fun send(bytes: ByteArray) {
            val packet = PacketFixtures.buildTcpDataPacket(
                localAddr, localPort, remoteAddr, fakeTlsServer.port, seq = deviceSeq, ack = 1, payload = bytes
            )
            deviceSeq += bytes.size
            connection.unwrapOutbound(packet.payload)
        }

        fun sendFin() {
            val packet = PacketFixtures.buildTcpDataPacket(
                localAddr, localPort, remoteAddr, fakeTlsServer.port, seq = deviceSeq, ack = 1, pshFlag = false, finFlag = true
            )
            connection.unwrapOutbound(packet.payload)
        }

        /** Returns the next non-empty TCP payload written back to the device, or null on timeout. */
        fun nextPayload(timeoutMs: Long = 10000): ByteArray? {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                if (deviceWriter.sentMessages.size > nextMessageIndex) {
                    val ipPacket = deviceWriter.sentMessages[nextMessageIndex++].obj as IpPacket
                    val payload = (ipPacket.payload as TcpPacket).payload?.rawData
                    if (payload != null && payload.isNotEmpty()) {
                        return payload
                    }
                } else {
                    Thread.sleep(10)
                }
            }
            return null
        }
    }

    /**
     * Drives [driver]'s client handshake through [flow]. Returns null once the handshake finishes,
     * or the [SSLException] the client raised. In that case the client's resulting alert is sent
     * first, as a real TLS client would do.
     */
    private fun runClientHandshake(flow: Flow, driver: FakeClientTlsDriver): SSLException? {
        flow.send(driver.wrap()!!) // ClientHello
        val deadline = System.currentTimeMillis() + 20000
        while (!driver.isHandshakeFinished()) {
            if (System.currentTimeMillis() > deadline) {
                fail("client handshake did not finish, status=${driver.handshakeStatus}")
            }
            val payload = flow.nextPayload(timeoutMs = 200) ?: continue
            // both calls are inside the try: JSSE runs certificate checks as delegated tasks and
            // stores a failure there, so a rejection can surface from the following wrap() rather
            // than from unwrap() itself
            try {
                driver.unwrap(payload)
                while (driver.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    val out = driver.wrap() ?: break
                    flow.send(out)
                }
            } catch (e: SSLException) {
                // after a fatal error the engine wants to wrap its alert; send it before giving up
                try {
                    driver.wrap()?.let { flow.send(it) }
                } catch (wrapError: SSLException) {
                    // no alert available
                }
                return e
            }
        }
        return null
    }

    private fun rejectingTrustManager() = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            throw CertificateException("test client does not trust Heimdall's CA")
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /** Keeps the upstream side of a connection open until the proxy closes it. */
    private fun holdUntilClosed(socket: SSLSocket) {
        try {
            val buf = ByteArray(8192)
            while (socket.inputStream.read(buf) >= 0) {
                // discard
            }
        } catch (e: Exception) {
            // closed
        }
    }

    private fun suspectCount(): Int {
        val field = TlsPassthroughCache::class.java.getDeclaredField("suspectCounts")
        field.isAccessible = true
        val counts = field.get(cache) as Map<*, *>
        return (counts.values.firstOrNull() as Int?) ?: 0
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
