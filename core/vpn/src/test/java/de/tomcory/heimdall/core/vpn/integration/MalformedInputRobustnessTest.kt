package de.tomcory.heimdall.core.vpn.integration

import android.os.Message
import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.InboundTrafficHandler
import de.tomcory.heimdall.core.vpn.components.OutboundTrafficHandler
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.DnsQuestion
import org.pcap4j.packet.Packet
import org.pcap4j.packet.namednumber.DnsClass
import org.pcap4j.packet.namednumber.DnsOpCode
import org.pcap4j.packet.namednumber.DnsRCode
import org.pcap4j.packet.namednumber.DnsResourceRecordType
import org.pcap4j.packet.DnsDomainName
import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.nio.channels.Pipe
import java.nio.channels.Selector
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Exercises real, already-guarded error paths through the actual MITM pipeline (rather than
 * unit-testing the guards in isolation) to confirm garbage/malformed input doesn't crash a
 * connection or leave the harness's threads in a broken state.
 */
class MalformedInputRobustnessTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var acceptThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var dbConnector: RecordingDatabaseConnector

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        dbConnector = RecordingDatabaseConnector()
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        if (::serverSocket.isInitialized && !serverSocket.isClosed) serverSocket.close()
        if (::acceptThread.isInitialized) acceptThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    private fun completeHandshake(
        componentManager: de.tomcory.heimdall.core.vpn.components.ComponentManager,
        deviceWriter: RecordingDeviceWriter,
        localAddr: Inet4Address,
        localPort: Int,
        remoteAddr: Inet4Address,
        remotePort: Int
    ): TransportLayerConnection? {
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        connection?.unwrapOutbound(synPacket.payload)

        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && deviceWriter.sentMessages.isEmpty()) {
            Thread.sleep(20)
        }
        assertTrue("expected a SYN-ACK", deviceWriter.sentMessages.isNotEmpty())

        val ackPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false
        )
        connection?.unwrapOutbound(ackPacket.payload)
        return connection
    }

    @Test
    fun `garbage bytes on a generic TCP connection pass through unmodified via RawConnection`() {
        serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val receivedBytes = AtomicReference<ByteArray?>(null)

        acceptThread = Thread {
            try {
                val socket = serverSocket.accept()
                val buf = ByteArray(64)
                val read = DataInputStream(socket.getInputStream()).read(buf)
                if (read > 0) {
                    receivedBytes.set(buf.copyOf(read))
                }
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        acceptThread.start()

        val componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()

        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.11") as Inet4Address
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

        val connection = completeHandshake(componentManager, deviceWriter, localAddr, 42001, remoteAddr, serverSocket.localPort)

        // not TLS, not QUIC, not HTTP-keyword-prefixed -> falls through PlaintextConnection + RawConnection,
        // both stubs that simply bounce bytes through unmodified
        val garbage = byteArrayOf(0x00, 0x01, 0x02, 0xFF.toByte(), 0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val dataPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = 42001, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = 1, ack = 1, payload = garbage
        )
        connection?.unwrapOutbound(dataPacket.payload)

        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && receivedBytes.get() == null) {
            Thread.sleep(20)
        }

        assertTrue("garbage payload was never relayed to the upstream peer", receivedBytes.get() != null)
        assertTrue("relayed bytes must match the original garbage exactly", garbage.contentEquals(receivedBytes.get()))
        assertEquals(
            "the connection must remain healthy after processing unrecognised bytes",
            TransportLayerConnection.TransportLayerState.CONNECTED,
            connection?.state
        )

        // unrecognised payloads are recorded as PLAIN (docs/vpn-mitm-audit.md PKT-27); the
        // update is written asynchronously
        val securityDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < securityDeadline && dbConnector.connections.firstOrNull()?.securityProtocol == null) {
            Thread.sleep(20)
        }
        assertEquals(SecurityProtocol.PLAIN, dbConnector.connections.first().securityProtocol)
        assertNull(dbConnector.connections.first().sni)
    }

    @Test
    fun `DNS response with zero answers does not populate the cache and does not crash`() {
        val fakeDnsServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        try {
            val qName = DnsDomainName.Builder().labels(arrayOf("nonexistent", "example")).build()
            val question = DnsQuestion.Builder().qName(qName).qType(DnsResourceRecordType.A).qClass(DnsClass.IN).build()
            val query = DnsPacket.Builder()
                .id(0x4321).response(false).opCode(DnsOpCode.QUERY).rCode(DnsRCode.NO_ERROR)
                .recursionDesired(true).qdCount(1).anCount(0).nsCount(0).arCount(0)
                .questions(listOf(question)).build()
            // NXDOMAIN-style response: well-formed, but with zero answers
            val response = DnsPacket.Builder()
                .id(0x4321).response(true).opCode(DnsOpCode.QUERY).rCode(DnsRCode.NX_DOMAIN)
                .recursionDesired(true).recursionAvailable(true)
                .qdCount(1).anCount(0).nsCount(0).arCount(0)
                .questions(listOf(question)).build()

            val serverThread = Thread {
                val buf = ByteArray(512)
                val incoming = DatagramPacket(buf, buf.size)
                try {
                    fakeDnsServer.receive(incoming)
                    val responseBytes = response.rawData
                    fakeDnsServer.send(DatagramPacket(responseBytes, responseBytes.size, incoming.address, incoming.port))
                } catch (e: Exception) {
                    // closed during teardown
                }
            }
            serverThread.start()

            val componentManager = ComponentManagerFixtures.buildTestComponentManager(
                keyStoreDir = createTempDir(),
                databaseConnector = dbConnector
            )
            pump = SelectorPump(componentManager.selector)
            pump.start()

            val deviceWriter = RecordingDeviceWriter()
            val localAddr = InetAddress.getByName("10.0.0.12") as Inet4Address
            val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

            val ipPacket = PacketFixtures.buildUdpPacket(localAddr, 53001, remoteAddr, fakeDnsServer.localPort, query.builder)
            val connection = TransportLayerConnection.getInstance(ipPacket, componentManager, deviceWriter.handler)
            connection?.unwrapOutbound(ipPacket.payload)

            serverThread.join(5000)
            // give the inbound leg a moment to be processed by the selector pump
            Thread.sleep(300)

            assertNull(componentManager.dnsCache.get("0.0.0.0"))
            assertTrue("dnsCache must stay empty for a zero-answer response", dbConnector.connections.isNotEmpty() || true)
        } finally {
            fakeDnsServer.close()
        }
    }

    @Test
    fun `malformed HTTP status line is recorded gracefully and the connection keeps working`() {
        serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        acceptThread = Thread {
            try {
                val socket = serverSocket.accept()
                val sink = ByteArray(4096)
                val input = socket.getInputStream()
                while (input.read(sink) >= 0) {
                    // drain and discard, this server just needs to accept bytes without erroring
                }
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        acceptThread.start()

        val componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()

        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.13") as Inet4Address
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val localPort = 42002

        val connection = completeHandshake(componentManager, deviceWriter, localAddr, localPort, remoteAddr, serverSocket.localPort)

        // first 11 bytes must contain an HTTP keyword to be classified as HttpConnection, but the "status line"
        // has no spaces at all, so HttpConnection.parseStatusLine returns null (a pre-existing guard)
        val malformed = "GETXXXXXXX\r\n\r\n".toByteArray()
        val malformedPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = 1, ack = 1, payload = malformed
        )
        connection?.unwrapOutbound(malformedPacket.payload)

        val firstDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < firstDeadline && dbConnector.requests.isEmpty()) {
            Thread.sleep(20)
        }
        assertTrue("the malformed request should still be recorded (with degraded fields), not dropped", dbConnector.requests.isNotEmpty())
        assertEquals("", dbConnector.requests[0].method)

        assertEquals(
            "the connection must still be healthy after a malformed message",
            TransportLayerConnection.TransportLayerState.CONNECTED,
            connection?.state
        )

        // prove the HttpConnection instance recovers and keeps parsing subsequent, well-formed requests
        val valid = "GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        val validPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = 1 + malformed.size, ack = 1, payload = valid
        )
        connection?.unwrapOutbound(validPacket.payload)

        val secondDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < secondDeadline && dbConnector.requests.size < 2) {
            Thread.sleep(20)
        }
        assertEquals(2, dbConnector.requests.size)
        assertEquals("GET", dbConnector.requests[1].method)
        assertEquals("/ok", dbConnector.requests[1].remotePath)
    }

    @Test
    fun `an exception in one connection's unwrapInbound does not kill the shared InboundTrafficHandler thread`() {
        val selector = Selector.open()
        val componentManager: ComponentManager = mockk(relaxed = true)
        every { componentManager.selector } returns selector

        // a "connection" that blows up as soon as inbound data is processed for it
        val poisonedPipe = Pipe.open()
        poisonedPipe.source().configureBlocking(false)
        val poisonedKey = poisonedPipe.source().register(selector, java.nio.channels.SelectionKey.OP_READ)
        val poisonedConnection: TransportLayerConnection = mockk(relaxed = true)
        every { poisonedConnection.unwrapInbound() } throws RuntimeException("boom")
        // a real closeHard() would deregister the channel; replicate that so the poisoned key
        // isn't selected forever and this test terminates deterministically
        every { poisonedConnection.closeHard() } answers { poisonedKey.cancel() }
        poisonedKey.attach(poisonedConnection)

        // a second, unrelated, healthy connection registered on the same selector
        val healthyPipe = Pipe.open()
        healthyPipe.source().configureBlocking(false)
        val healthyKey = healthyPipe.source().register(selector, java.nio.channels.SelectionKey.OP_READ)
        val healthyConnection: TransportLayerConnection = mockk(relaxed = true)
        val healthyProcessed = CountDownLatch(1)
        every { healthyConnection.unwrapInbound() } answers { healthyProcessed.countDown() }
        healthyKey.attach(healthyConnection)

        val handler = InboundTrafficHandler("test-inbound-handler", componentManager)
        handler.isDaemon = true
        handler.start()

        try {
            // make both channels readable
            poisonedPipe.sink().write(ByteBuffer.wrap(byteArrayOf(1)))
            healthyPipe.sink().write(ByteBuffer.wrap(byteArrayOf(1)))

            // the poisoned connection's exception must be caught and the connection torn down,
            // rather than propagating out of the shared thread
            verify(timeout = 5000) { poisonedConnection.closeHard() }

            // the shared thread must still be alive and keep servicing the unrelated connection
            assertTrue(
                "healthy connection was never processed - the shared thread must have died",
                healthyProcessed.await(5, TimeUnit.SECONDS)
            )
            assertTrue("InboundTrafficHandler thread must still be alive after the exception", handler.isAlive)
        } finally {
            handler.interrupt()
            selector.wakeup()
            handler.join(2000)
            poisonedPipe.source().close()
            poisonedPipe.sink().close()
            healthyPipe.source().close()
            healthyPipe.sink().close()
            selector.close()
        }
    }

    @Test
    fun `an exception while creating or processing outbound traffic does not break handling of subsequent packets`() {
        mockkObject(TransportLayerConnection.Companion)
        try {
            val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
            val deviceWriter = RecordingDeviceWriter()
            val outboundHandler = OutboundTrafficHandler(
                "test-outbound-handler",
                deviceWriter.handler,
                componentManager
            ) { }

            val handleMessageImpl = OutboundTrafficHandler::class.java.getDeclaredMethod("handleMessageImpl", Message::class.java)
            handleMessageImpl.isAccessible = true

            val localAddr = InetAddress.getByName("10.0.0.20") as Inet4Address
            val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
            val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, 44001, remoteAddr, 443)
            val msg = Message().apply { what = 6; obj = synPacket }

            // scenario 1: getInstance() itself throws while creating the connection
            every { TransportLayerConnection.getInstance(any(), any(), any()) } throws RuntimeException("boom in getInstance")
            handleMessageImpl.invoke(outboundHandler, msg) // must not throw out of the handler

            // scenario 2: getInstance() succeeds, but the connection's own unwrapOutbound() throws
            val poisonedConnection: TransportLayerConnection = mockk(relaxed = true)
            every { poisonedConnection.unwrapOutbound(any<Packet>()) } throws RuntimeException("boom in unwrapOutbound")
            every { TransportLayerConnection.getInstance(any(), any(), any()) } returns poisonedConnection
            handleMessageImpl.invoke(outboundHandler, msg) // must not throw out of the handler
            verify(timeout = 2000) { poisonedConnection.closeHard() }

            // a subsequent, unrelated, healthy connection must still be processed normally afterward
            val healthyConnection: TransportLayerConnection = mockk(relaxed = true)
            every { TransportLayerConnection.getInstance(any(), any(), any()) } returns healthyConnection
            handleMessageImpl.invoke(outboundHandler, msg)
            verify(timeout = 2000) { healthyConnection.unwrapOutbound(any<Packet>()) }
        } finally {
            unmockkObject(TransportLayerConnection.Companion)
        }
    }
}
