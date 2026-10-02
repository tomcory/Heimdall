package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for docs/vpn-mitm-audit.md PKT-39 (V-17): segments from the device are checked against
 * the next expected sequence number. The device retransmits whenever an ACK from the VPN is
 * late, and such a segment used to be forwarded to the remote host a second time.
 *
 * Every test sends segments to a local server that reads until the end of the stream, and then
 * compares what the server received with what the device meant to send.
 */
class TcpSegmentValidationTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var serverThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var connection: TransportLayerConnection

    private val acceptedSocket = AtomicReference<Socket?>(null)
    private val receivedByServer = AtomicReference<String?>(null)

    private val localAddr = InetAddress.getByName("10.0.0.60") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

    private val first = "first-segment;".toByteArray()
    private val second = "second-segment;".toByteArray()
    private val third = "third-segment;".toByteArray()

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        serverSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = RecordingDatabaseConnector()
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()
        deviceWriter = RecordingDeviceWriter()

        serverThread = Thread {
            try {
                val socket = serverSocket.accept()
                acceptedSocket.set(socket)
                receivedByServer.set(String(socket.getInputStream().readBytes()))
                socket.close()
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        serverThread.start()
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        acceptedSocket.get()?.close()
        if (!serverSocket.isClosed) serverSocket.close()
        if (::serverThread.isInitialized) serverThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    private fun send(seq: Int, payload: ByteArray = ByteArray(0), finFlag: Boolean = false) {
        val packet = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = LOCAL_PORT, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = seq, ack = 1, payload = payload, pshFlag = payload.isNotEmpty(), finFlag = finFlag
        )
        connection.unwrapOutbound(packet.payload)
    }

    /**
     * Opens a TCP connection to the server and completes the device-side handshake.
     *
     * @return the sequence number of the device's first data byte.
     */
    private fun connect(initialSeq: Int = 0): Int {
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, LOCAL_PORT, remoteAddr, serverSocket.localPort, seq = initialSeq)
        connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        send(seq = initialSeq + 1)
        assertEquals(TransportLayerState.CONNECTED, connection.state)
        return initialSeq + 1
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

    /** Sends the device's FIN at [seq] and returns the byte stream the server received up to it. */
    private fun finishAndGetServerStream(seq: Int): String {
        send(seq = seq, finFlag = true)
        awaitUntil("the server never saw the end of the stream") { receivedByServer.get() != null }
        return receivedByServer.get()!!
    }

    @Test
    fun `a retransmitted segment is acknowledged again but not forwarded twice`() {
        val start = connect()
        send(seq = start, payload = first)
        val messagesBefore = deviceWriter.sentMessages.size

        send(seq = start, payload = first)

        val reAck = segmentsSince(messagesBefore).single()
        assertTrue(reAck.header.ack)
        assertFalse(reAck.header.rst)
        assertEquals("the retransmission must be answered with the unchanged expected sequence number", start + first.size, reAck.header.acknowledgmentNumber)

        send(seq = start + first.size, payload = second)
        assertEquals(start + first.size + second.size, segmentsSince(messagesBefore).last().header.acknowledgmentNumber)

        assertEquals(String(first + second), finishAndGetServerStream(start + first.size + second.size))
        assertFalse(segmentsSince(0).any { it.header.rst })
    }

    @Test
    fun `only the new part of an overlapping segment is forwarded`() {
        val start = connect()
        send(seq = start, payload = first)
        val messagesBefore = deviceWriter.sentMessages.size

        // the device retransmits the last 5 bytes of the first segment together with new data
        val overlap = 5
        send(seq = start + first.size - overlap, payload = first.copyOfRange(first.size - overlap, first.size) + second)

        assertEquals(start + first.size + second.size, segmentsSince(messagesBefore).single().header.acknowledgmentNumber)
        assertEquals(String(first + second), finishAndGetServerStream(start + first.size + second.size))
    }

    @Test
    fun `a segment that follows a gap is dropped until the missing one has arrived`() {
        val start = connect()
        val messagesBefore = deviceWriter.sentMessages.size

        // the second segment overtakes the first
        send(seq = start + first.size, payload = second)

        val duplicateAck = segmentsSince(messagesBefore).single()
        assertFalse(duplicateAck.header.rst)
        assertEquals("the ACK must still ask for the missing segment", start, duplicateAck.header.acknowledgmentNumber)
        assertEquals(TransportLayerState.CONNECTED, connection.state)

        // the device sends the missing segment and retransmits the one that was dropped
        send(seq = start, payload = first)
        send(seq = start + first.size, payload = second)

        assertEquals(String(first + second), finishAndGetServerStream(start + first.size + second.size))
    }

    @Test
    fun `duplicates and gaps are recognised across the sequence number wrap-around`() {
        // 10 below the wrap: the first segment ends beyond it
        val start = connect(initialSeq = -11)
        assertEquals(-10, start)

        send(seq = start, payload = first)
        val afterFirst = start + first.size
        assertTrue("the first segment must cross the wrap-around", start < 0 && afterFirst > 0)

        var messagesBefore = deviceWriter.sentMessages.size
        send(seq = start, payload = first) // a retransmission from below the wrap
        assertEquals(afterFirst, segmentsSince(messagesBefore).single().header.acknowledgmentNumber)

        messagesBefore = deviceWriter.sentMessages.size
        send(seq = afterFirst + second.size, payload = third) // a gap
        assertEquals(afterFirst, segmentsSince(messagesBefore).single().header.acknowledgmentNumber)

        send(seq = afterFirst, payload = second)
        send(seq = afterFirst + second.size, payload = third)

        assertEquals(String(first + second + third), finishAndGetServerStream(afterFirst + second.size + third.size))
    }

    @Test
    fun `a gap right below the wrap-around is not mistaken for a retransmission`() {
        // the expected sequence number is just below the wrap, the segment that arrives just above
        val start = connect(initialSeq = -6)
        val messagesBefore = deviceWriter.sentMessages.size

        send(seq = start + first.size, payload = second)
        assertTrue(start < 0 && start + first.size > 0)
        assertEquals(start, segmentsSince(messagesBefore).single().header.acknowledgmentNumber)

        send(seq = start, payload = first)
        assertEquals(String(first), finishAndGetServerStream(start + first.size))
    }

    @Test
    fun `a FIN that follows a gap does not end the stream`() {
        val start = connect()
        send(seq = start, payload = first)
        val messagesBefore = deviceWriter.sentMessages.size

        // the segment carrying "second" was lost, the FIN after it arrives
        send(seq = start + first.size + second.size, finFlag = true)

        assertEquals(TransportLayerState.CONNECTED, connection.state)
        assertEquals(start + first.size, segmentsSince(messagesBefore).single().header.acknowledgmentNumber)

        send(seq = start + first.size, payload = second)
        assertEquals(String(first + second), finishAndGetServerStream(start + first.size + second.size))
        assertTrue(
            "the in-order FIN must be accepted",
            connection.state == TransportLayerState.HALF_CLOSED || connection.state == TransportLayerState.CLOSING
        )
    }

    @Test
    fun `a retransmitted segment that carries data and the FIN is not forwarded twice`() {
        val start = connect()
        send(seq = start, payload = first)

        // data and FIN in one segment, then the same segment again
        send(seq = start + first.size, payload = second, finFlag = true)
        awaitUntil("the server never saw the end of the stream") { receivedByServer.get() != null }
        val messagesBefore = deviceWriter.sentMessages.size
        send(seq = start + first.size, payload = second, finFlag = true)

        assertEquals(String(first + second), receivedByServer.get())
        val answers = segmentsSince(messagesBefore)
        assertFalse("a retransmitted FIN must not reset the connection", answers.any { it.header.rst })
        assertTrue(
            "the retransmission must be answered with an acknowledgement of the FIN",
            answers.isNotEmpty() && answers.all { it.header.acknowledgmentNumber == start + first.size + second.size + 1 }
        )
    }

    @Test
    fun `data completes the handshake when the device's handshake ACK was lost`() {
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, LOCAL_PORT, remoteAddr, serverSocket.localPort)
        connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        assertEquals(TransportLayerState.CONNECTING, connection.state)

        // the first data segment arrives without the empty ACK before it
        send(seq = 1, payload = first)

        assertEquals(TransportLayerState.CONNECTED, connection.state)
        assertFalse(segmentsSince(0).any { it.header.rst })
        // the handshake ACK arrives late and changes nothing
        send(seq = 1)
        assertEquals(String(first), finishAndGetServerStream(1 + first.size))
    }

    @Test
    fun `a keep-alive probe is acknowledged and forwards nothing`() {
        val start = connect()
        send(seq = start, payload = first)
        val afterFirst = start + first.size
        var messagesBefore = deviceWriter.sentMessages.size

        // the probe without data, as Linux sends it
        send(seq = afterFirst - 1)
        assertEquals(afterFirst, segmentsSince(messagesBefore).single().header.acknowledgmentNumber)

        // the probe with one byte of filler, as some other stacks send it
        messagesBefore = deviceWriter.sentMessages.size
        send(seq = afterFirst - 1, payload = byteArrayOf(0))
        assertEquals(afterFirst, segmentsSince(messagesBefore).single().header.acknowledgmentNumber)

        // an ordinary empty ACK is still not answered
        messagesBefore = deviceWriter.sentMessages.size
        send(seq = afterFirst)
        assertEquals(messagesBefore, deviceWriter.sentMessages.size)

        assertEquals(String(first), finishAndGetServerStream(afterFirst))
    }

    companion object {
        private const val LOCAL_PORT = 47000
    }
}
