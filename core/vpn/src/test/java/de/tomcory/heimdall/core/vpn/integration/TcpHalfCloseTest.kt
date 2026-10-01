package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TcpConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection.TransportLayerState
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for docs/vpn-mitm-audit.md PKT-30 (V-42): a client may finish sending (TCP FIN) and still
 * wait for the remote host's reply. The FIN used to close the outward-facing socket at once, so
 * that reply was lost.
 */
class TcpHalfCloseTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var serverThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var dbConnector: RecordingDatabaseConnector
    private lateinit var synPacket: IpV4Packet

    private val acceptedSocket = AtomicReference<Socket?>(null)
    private val requestSeenByServer = AtomicReference<String?>(null)

    private val localAddr = InetAddress.getByName("10.0.0.50") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private val request = "GET / HTTP/1.0\r\n\r\n".toByteArray()
    private val reply = "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        dbConnector = RecordingDatabaseConnector()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()
        deviceWriter = RecordingDeviceWriter()
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        acceptedSocket.get()?.close()
        if (!serverSocket.isClosed) serverSocket.close()
        if (::serverThread.isInitialized) serverThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    /**
     * Starts the fake server. It reads until the client's end of stream, which it only sees
     * once the half-close has been passed on, and then either replies and closes or, with
     * [replyAndClose] false, keeps the connection open without sending anything.
     */
    private fun startServer(replyAndClose: Boolean) {
        serverThread = Thread {
            try {
                val socket = serverSocket.accept()
                acceptedSocket.set(socket)
                requestSeenByServer.set(String(socket.getInputStream().readBytes()))
                if (replyAndClose) {
                    socket.getOutputStream().write(reply.toByteArray())
                    socket.getOutputStream().flush()
                    socket.close()
                }
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        serverThread.start()
    }

    private fun sendFromDevice(seq: Int, payload: ByteArray = ByteArray(0), finFlag: Boolean = false, ack: Int = 1, connection: TransportLayerConnection) {
        val packet = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = LOCAL_PORT, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = seq, ack = ack, payload = payload, pshFlag = payload.isNotEmpty(), finFlag = finFlag
        )
        connection.unwrapOutbound(packet.payload)
    }

    /** Opens a TCP connection to the fake server and completes the device-side handshake. */
    private fun connect(): TransportLayerConnection {
        synPacket = PacketFixtures.buildTcpSynPacket(localAddr, LOCAL_PORT, remoteAddr, serverSocket.localPort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        sendFromDevice(seq = 1, connection = connection)
        assertEquals(TransportLayerState.CONNECTED, connection.state)
        return connection
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 5000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !condition()) {
            Thread.sleep(20)
        }
        assertTrue(message, condition())
    }

    private fun segmentsSince(index: Int): List<TcpPacket> {
        return deviceWriter.sentMessages.drop(index).map { (it.obj as IpPacket).payload as TcpPacket }
    }

    /** Replaces the connection's lazily-created encryption layer (the field is private to the transport layer). */
    private fun installEncryptionLayer(connection: TransportLayerConnection, layer: EncryptionLayerConnection) {
        val field = TransportLayerConnection::class.java.getDeclaredField("encryptionLayer")
        field.isAccessible = true
        field.set(connection, layer)
    }

    /** Encryption layer stand-in that cannot carry a half-close, like a MitM'd TLS connection. */
    private class NoHalfCloseEncryptionLayer(
        transportLayer: TransportLayerConnection,
        componentManager: ComponentManager
    ) : EncryptionLayerConnection(0, transportLayer, componentManager) {
        override val protocol = "TEST"
        override val supportsHalfClose = false
        override fun unwrapOutbound(payload: ByteArray) {}
        override fun unwrapOutbound(packet: Packet) {}
        override fun unwrapInbound(payload: ByteArray) {}
        override fun wrapOutbound(payload: ByteArray) {}
        override fun wrapInbound(payload: ByteArray) {}
    }

    @Test
    fun `the reply still reaches the device after it has sent its FIN`() {
        startServer(replyAndClose = true)
        val connection = connect()

        sendFromDevice(seq = 1, payload = request, connection = connection)
        val messagesBeforeFin = deviceWriter.sentMessages.size

        // the device has nothing more to send: FIN right after the request
        sendFromDevice(seq = 1 + request.size, finFlag = true, connection = connection)

        // the server only answers once it sees the end of the request stream, so a reply proves
        // the half-close was passed on and the connection stayed open for it
        awaitUntil("the reply never reached the device") {
            segmentsSince(messagesBeforeFin).any { it.payload != null && String(it.payload.rawData).contains("hello") }
        }
        assertEquals(String(request), requestSeenByServer.get())

        // the server closed after replying, so our FIN-ACK follows and we wait for the final ACK
        awaitUntil("expected the connection to move to CLOSING") { connection.state == TransportLayerState.CLOSING }
        val segments = segmentsSince(messagesBeforeFin)
        assertFalse("a half-close must not reset the device's connection", segments.any { it.header.rst })
        assertFalse("the ACK for the device's FIN must not carry our FIN", segments.first().header.fin)
        assertTrue("our FIN must come last, after the reply", segments.last().header.fin)
        assertEquals("exactly one FIN must be sent", 1, segments.count { it.header.fin })

        // the device's sequence numbers start at 0: the SYN, the request and the FIN are all
        // acknowledged by every segment sent after the FIN
        val expectedAck = 1L + request.size + 1
        assertTrue(
            "every segment after the FIN must acknowledge it exactly once",
            segments.all { it.header.acknowledgmentNumberAsLong == expectedAck }
        )

        // the device acknowledges our FIN, which ends the connection
        sendFromDevice(seq = 2 + request.size, ack = segments.last().header.sequenceNumber + 1, connection = connection)
        assertEquals(TransportLayerState.CLOSED, connection.state)
        assertNull("the connection must leave the cache once the close completes", ConnectionCache.findConnection(synPacket))

        // the request and the response were both recorded
        awaitUntil("expected the response to be persisted") { dbConnector.responses.isNotEmpty() }
        assertEquals(200, dbConnector.responses.first().statusCode)
        awaitUntil("expected the inbound bytes to be counted") { dbConnector.connections.first().bytesIn == reply.length.toLong() }
    }

    @Test
    fun `a retransmitted FIN while half-closed is acknowledged again and changes nothing else`() {
        startServer(replyAndClose = false)
        val connection = connect()

        sendFromDevice(seq = 1, finFlag = true, connection = connection)
        assertEquals(TransportLayerState.HALF_CLOSED, connection.state)
        val firstAck = segmentsSince(deviceWriter.sentMessages.size - 1).single()
        val messagesAfterFirstFin = deviceWriter.sentMessages.size

        sendFromDevice(seq = 1, finFlag = true, connection = connection)

        assertEquals(messagesAfterFirstFin + 1, deviceWriter.sentMessages.size)
        val secondAck = segmentsSince(messagesAfterFirstFin).single()
        assertFalse(secondAck.header.fin)
        assertFalse(secondAck.header.rst)
        assertEquals(
            "the FIN must not be counted twice",
            firstAck.header.acknowledgmentNumberAsLong,
            secondAck.header.acknowledgmentNumberAsLong
        )
        assertEquals(firstAck.header.sequenceNumberAsLong, secondAck.header.sequenceNumberAsLong)
        assertEquals(TransportLayerState.HALF_CLOSED, connection.state)
        assertNotNull(ConnectionCache.findConnection(synPacket))
    }

    @Test
    fun `data from the device after its FIN aborts the connection`() {
        startServer(replyAndClose = false)
        val connection = connect()

        sendFromDevice(seq = 1, finFlag = true, connection = connection)
        assertEquals(TransportLayerState.HALF_CLOSED, connection.state)

        val messagesBeforeData = deviceWriter.sentMessages.size
        sendFromDevice(seq = 2, payload = request, connection = connection)

        assertNull(ConnectionCache.findConnection(synPacket))
        assertTrue(
            "the device must be told with an RST that the connection is gone",
            segmentsSince(messagesBeforeData).any { it.header.rst }
        )
    }

    @Test
    fun `a half-closed connection whose remote host stays silent is aborted by the sweep`() {
        startServer(replyAndClose = false)
        val connection = connect()
        sendFromDevice(seq = 1, finFlag = true, connection = connection)
        assertEquals(TransportLayerState.HALF_CLOSED, connection.state)

        // not yet stale
        TcpConnection.sweepStaleConnections(halfClosedTimeoutMs = 60_000, now = System.currentTimeMillis())
        assertNotNull("a recently half-closed connection must not be reaped", ConnectionCache.findConnection(synPacket))

        TcpConnection.sweepStaleConnections(halfClosedTimeoutMs = 60_000, now = System.currentTimeMillis() + 120_000)

        assertNull("expected the stale half-closed connection to be removed from the cache", ConnectionCache.findConnection(synPacket))
        assertTrue(
            "the device must be told with an RST that the connection is gone",
            segmentsSince(0).last().header.rst
        )
    }

    @Test
    fun `the sweep leaves connections alone that are not half-closed`() {
        startServer(replyAndClose = false)
        val connection = connect()

        TcpConnection.sweepStaleConnections(halfClosedTimeoutMs = 0, now = System.currentTimeMillis() + 1_000_000)

        assertEquals(TransportLayerState.CONNECTED, connection.state)
        assertNotNull(ConnectionCache.findConnection(synPacket))
    }

    @Test
    fun `a connection whose encryption layer cannot carry a half-close is closed fully on FIN`() {
        startServer(replyAndClose = false)
        val connection = connect()
        installEncryptionLayer(connection, NoHalfCloseEncryptionLayer(connection, componentManager))
        val messagesBeforeFin = deviceWriter.sentMessages.size

        sendFromDevice(seq = 1, finFlag = true, connection = connection)

        // the previous behaviour: the outward-facing channel is closed and our FIN-ACK is sent at once
        assertEquals(TransportLayerState.CLOSING, connection.state)
        val segments = segmentsSince(messagesBeforeFin)
        assertEquals(1, segments.size)
        assertTrue(segments.single().header.fin)
        assertTrue(segments.single().header.ack)
        assertFalse(segments.single().header.rst)

        // the server sees the full close as end of stream
        awaitUntil("the fake server never saw the connection close") { requestSeenByServer.get() != null }
    }

    companion object {
        private const val LOCAL_PORT = 43001
    }
}
