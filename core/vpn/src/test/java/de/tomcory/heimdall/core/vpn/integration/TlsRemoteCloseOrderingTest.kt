package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.FakeClientTlsDriver
import de.tomcory.heimdall.core.vpn.integration.support.FakeTlsServer
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLSocket

/**
 * Tests for docs/vpn-mitm-audit.md PKT-36 (V-46): a server that sends its response and closes
 * the connection at once. The transport layer sees the end of the stream on the selector thread,
 * while the TLS layer is still working through the response on its own dispatcher. The close
 * used to be passed on to the device straight away, ahead of the response data, so the device
 * discarded the data and the app lost the response.
 */
class TlsRemoteCloseOrderingTest {

    private lateinit var fakeTlsServer: FakeTlsServer
    private lateinit var componentManager: ComponentManager
    private lateinit var dbConnector: RecordingDatabaseConnector
    private lateinit var pump: SelectorPump

    private val hostname = "example.com"
    private val localAddr = InetAddress.getByName("10.0.0.80") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

    // large enough to need several TLS records and TCP segments
    private val body = "0123456789abcdef".repeat(2500)
    private val response = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        if (::fakeTlsServer.isInitialized) fakeTlsServer.close()
        ConnectionCache.closeAllAndClear()
    }

    private fun start(doMitm: Boolean) {
        fakeTlsServer = FakeTlsServer(hostname)
        dbConnector = RecordingDatabaseConnector()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            doMitm = doMitm,
            databaseConnector = dbConnector
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()
    }

    /** Reads the request, answers, and closes the socket without waiting for anything. */
    private fun respondAndCloseAtOnce(socket: SSLSocket) {
        val buf = ByteArray(8192)
        socket.inputStream.read(buf)
        socket.outputStream.write(response.toByteArray())
        socket.outputStream.flush()
        socket.close()
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 10000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !condition()) {
            Thread.sleep(10)
        }
        assertTrue(message, condition())
    }

    /**
     * Runs one request against the fake server through a fresh device-side connection and checks
     * what the device was sent, in the order it was sent.
     */
    private fun requestAndCheckOrdering(localPort: Int) {
        fakeTlsServer.acceptOnce(::respondAndCloseAtOnce)

        val deviceWriter = RecordingDeviceWriter()
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, fakeTlsServer.port)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        connection.unwrapOutbound(
            PacketFixtures.buildTcpDataPacket(localAddr, localPort, remoteAddr, fakeTlsServer.port, seq = 1, ack = 1, pshFlag = false).payload
        )

        var deviceSeq = 1
        fun send(bytes: ByteArray) {
            val packet = PacketFixtures.buildTcpDataPacket(localAddr, localPort, remoteAddr, fakeTlsServer.port, seq = deviceSeq, ack = 1, payload = bytes)
            deviceSeq += bytes.size
            connection.unwrapOutbound(packet.payload)
        }

        var nextIndex = deviceWriter.sentMessages.size
        fun nextSegment(timeoutMs: Long): TcpPacket? {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                if (deviceWriter.sentMessages.size > nextIndex) {
                    return (deviceWriter.sentMessages[nextIndex++].obj as IpPacket).payload as TcpPacket
                }
                Thread.sleep(5)
            }
            return null
        }

        // TLS handshake between the fake app and whatever the VPN presents to it
        val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port)
        send(driver.wrap()!!)
        val handshakeDeadline = System.currentTimeMillis() + 20000
        while (!driver.isHandshakeFinished()) {
            if (System.currentTimeMillis() > handshakeDeadline) fail("client handshake did not finish, status=${driver.handshakeStatus}")
            val payload = nextSegment(200)?.payload?.rawData ?: continue
            if (payload.isEmpty()) continue
            driver.unwrap(payload)
            while (driver.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                send(driver.wrap() ?: break)
            }
        }

        send(driver.wrap("GET / HTTP/1.1\r\nHost: $hostname\r\nConnection: close\r\n\r\n".toByteArray())!!)

        // collect everything the device is sent until the connection is closed towards it
        val decrypted = ByteArrayOutputStream()
        var closingSegment: TcpPacket? = null
        var expectedSeq: Int? = null
        while (closingSegment == null) {
            val segment = nextSegment(10000) ?: break
            val payload = segment.payload?.rawData ?: ByteArray(0)
            if (payload.isNotEmpty()) {
                // data must arrive as one gapless byte stream
                expectedSeq?.let { assertEquals("data segments must be contiguous", it, segment.header.sequenceNumber) }
                expectedSeq = segment.header.sequenceNumber + payload.size
                driver.unwrap(payload)?.let { decrypted.write(it) }
            }
            if (segment.header.fin || segment.header.rst) {
                closingSegment = segment
            }
        }
        assertNotNull("the remote close never reached the device", closingSegment)
        assertTrue(
            "a server that closes normally must be passed on as a FIN, not as a reset",
            closingSegment!!.header.fin && closingSegment.header.ack && !closingSegment.header.rst
        )

        assertEquals(
            "the device must have received the complete response before the connection was closed towards it",
            response,
            decrypted.toString(Charsets.UTF_8.name())
        )
        assertEquals(
            "the closing segment must follow the last data byte, not precede it",
            expectedSeq,
            closingSegment!!.header.sequenceNumber
        )

        // nothing that carries data may come after the close
        Thread.sleep(300)
        val late = deviceWriter.sentMessages.drop(nextIndex).map { (it.obj as IpPacket).payload as TcpPacket }
        assertFalse(
            "no data may be sent to the device after the connection was closed towards it",
            late.any { (it.payload?.rawData?.size ?: 0) > 0 }
        )
    }

    @Test
    fun `MitM - the response is delivered before the remote close`() {
        start(doMitm = true)
        // several rounds, because what is being tested is a race
        repeat(5) { round -> requestAndCheckOrdering(localPort = 48000 + round) }

        awaitUntil("expected every response to be persisted") { dbConnector.responses.size == 5 }
        assertTrue(dbConnector.responses.all { it.statusCode == 200 && it.content == body })
    }

    @Test
    fun `passthrough - the response is delivered before the remote close`() {
        start(doMitm = false)
        repeat(5) { round -> requestAndCheckOrdering(localPort = 48100 + round) }
    }
}
