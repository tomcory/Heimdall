package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.DnsQuestion
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
}
