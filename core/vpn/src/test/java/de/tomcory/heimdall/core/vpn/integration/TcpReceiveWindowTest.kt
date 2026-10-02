package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TcpConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection.TransportLayerState
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for docs/vpn-mitm-audit.md PKT-42 (V-49): data for the device is sent only as far as the
 * receive window it advertises allows. It used to be sent as fast as the remote host delivered
 * it, and what the device had no room for was lost.
 *
 * The device side here acknowledges and advertises windows like a real TCP stack would: with the
 * real acknowledgement numbers, and only for what it was actually sent.
 */
class TcpReceiveWindowTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var serverThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var connection: TransportLayerConnection

    private val acceptedSocket = AtomicReference<Socket?>(null)
    private val serverDone = AtomicBoolean(false)

    private val localAddr = InetAddress.getByName("10.0.0.90") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

    // what the fake device has received and acknowledged so far
    private val received = ByteArrayOutputStream()
    private var nextSegmentIndex = 0
    private var ourInitialSeq = 0
    private var finSeen: TcpPacket? = null

    /** The acknowledgement number for everything received so far. */
    private val ackNumber: Int
        get() = ourInitialSeq + 1 + received.size() + (if (finSeen != null) 1 else 0)

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
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        acceptedSocket.get()?.close()
        if (!serverSocket.isClosed) serverSocket.close()
        if (::serverThread.isInitialized) serverThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    private fun pattern(size: Int) = ByteArray(size) { (it * 31 + it / 251).toByte() }

    /** Starts a server that sends [data] to whoever connects and then closes the connection. */
    private fun startServer(data: ByteArray) {
        serverThread = Thread {
            try {
                val socket = serverSocket.accept()
                acceptedSocket.set(socket)
                socket.getOutputStream().write(data)
                socket.getOutputStream().flush()
                serverDone.set(true)
                socket.close()
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        serverThread.start()
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 10000, condition: () -> Boolean) {
        // the condition is evaluated once per round: some of the conditions used here consume what they find
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(10)
        }
        fail(message)
    }

    private fun segments(): List<TcpPacket> = deviceWriter.sentMessages.map { (it.obj as IpPacket).payload as TcpPacket }

    /** Sends an empty ACK from the device for everything received so far, advertising [window]. */
    private fun ack(window: Int) {
        val packet = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = LOCAL_PORT, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = 1, ack = ackNumber, window = window
        )
        connection.unwrapOutbound(packet.payload)
    }

    /** Opens the connection with a SYN that advertises [window] and completes the handshake. */
    private fun connect(window: Int) {
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, LOCAL_PORT, remoteAddr, serverSocket.localPort, window = window)
        connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        val synAck = segments().first()
        assertTrue(synAck.header.syn && synAck.header.ack)
        ourInitialSeq = synAck.header.sequenceNumber
        nextSegmentIndex = 1
        ack(window)
        // CONNECTED, unless the server has already sent everything and closed
        assertTrue(connection.state == TransportLayerState.CONNECTED || connection.state == TransportLayerState.CLOSING)
    }

    /**
     * Takes in every segment sent to the device since the last call, the way a receiver would:
     * data must continue exactly where the previous segment ended.
     *
     * @return the number of data bytes taken in.
     */
    private fun receive(): Int {
        var bytes = 0
        val all = segments()
        while (nextSegmentIndex < all.size) {
            val segment = all[nextSegmentIndex++]
            assertFalse("the connection must not be reset", segment.header.rst)
            val payload = segment.payload?.rawData ?: ByteArray(0)
            if (payload.isNotEmpty()) {
                assertFalse("no data may follow the FIN", finSeen != null)
                assertEquals("data must arrive in order and without gaps", ackNumber, segment.header.sequenceNumber)
                received.write(payload)
                bytes += payload.size
            }
            if (segment.header.fin) {
                assertEquals("the FIN must follow the last data byte", ackNumber, segment.header.sequenceNumber + payload.size)
                finSeen = segment
            }
        }
        return bytes
    }

    /** Waits until nothing more arrives for a moment and returns the data bytes that did. */
    private fun receiveUntilQuiet(quietMs: Long = 250): Int {
        var total = 0
        var quietSince = System.currentTimeMillis()
        while (System.currentTimeMillis() - quietSince < quietMs) {
            val bytes = receive()
            if (bytes > 0 || finSeen != null && total == 0) {
                total += bytes
                quietSince = System.currentTimeMillis()
                if (finSeen != null) break
            }
            Thread.sleep(10)
        }
        return total
    }

    @Test
    fun `nothing is sent beyond the window, and everything arrives as it opens`() {
        val data = pattern(200_000)
        startServer(data)
        connect(window = 1000)

        // the first window's worth, and not a byte more
        assertEquals(1000, receiveUntilQuiet())

        // acknowledged, but the window stays shut: nothing may be sent
        ack(window = 0)
        assertEquals(0, receiveUntilQuiet())

        // open it in steps of different sizes
        for (window in listOf(1, 500, 3000, 20_000, 65535)) {
            ack(window)
            val expected = minOf(window, data.size - received.size())
            assertEquals("exactly the advertised window must be filled", expected, receiveUntilQuiet())
        }

        // an ACK that does not cover everything leaves only the rest of the window open
        val before = received.size()
        val partial = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = LOCAL_PORT, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = 1, ack = ackNumber - 10_000, window = 30_000
        )
        connection.unwrapOutbound(partial.payload)
        assertEquals(20_000, receiveUntilQuiet())
        assertEquals(before + 20_000, received.size())

        // take the rest
        while (finSeen == null) {
            ack(window = 65535)
            awaitUntil("the rest of the data never arrived ") { receive() > 0 || finSeen != null }
        }
        assertArrayEquals("the device must have received exactly what the server sent", data, received.toByteArray())
    }

    @Test
    fun `the remote host is not read while the device takes nothing`() {
        // far more than the socket buffers between the server and the VPN can hold
        val data = pattern(16 * 1024 * 1024)
        startServer(data)
        connect(window = 4000)

        assertEquals(4000, receiveUntilQuiet())
        Thread.sleep(1000)
        assertFalse(
            "the server must be held up by flow control while the device's window is shut",
            serverDone.get()
        )
        assertEquals("nothing more may have been sent to the device", 0, receive())

        // now take everything, as fast as it comes
        val deadline = System.currentTimeMillis() + 60_000
        while (finSeen == null && System.currentTimeMillis() < deadline) {
            ack(window = 65535)
            if (receive() == 0) Thread.sleep(1)
        }
        assertTrue("the transfer did not finish", finSeen != null)
        assertTrue(serverDone.get())
        assertArrayEquals(data, received.toByteArray())
    }

    @Test
    fun `the FIN waits for the data that the window holds back`() {
        val data = pattern(50_000)
        startServer(data)
        connect(window = 10_000)

        // the server has sent everything and closed, the device has room for a fifth of it
        awaitUntil("the server should be done at once") { serverDone.get() }
        assertEquals(10_000, receiveUntilQuiet(quietMs = 500))
        assertEquals("the FIN must not overtake the data", null, finSeen)
        assertEquals(TransportLayerState.CLOSING, connection.state)

        while (finSeen == null) {
            ack(window = 10_000)
            assertTrue("no more than the window may be sent at once", receiveUntilQuiet() <= 10_000)
        }
        assertArrayEquals(data, received.toByteArray())

        // the device closes its side as well, acknowledging our FIN
        val fin = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = LOCAL_PORT, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = 1, ack = ackNumber, finFlag = true
        )
        connection.unwrapOutbound(fin.payload)
        assertEquals(TransportLayerState.CLOSED, connection.state)
    }

    @Test
    fun `a device that leaves data waiting is asked for its window`() {
        val data = pattern(30_000)
        startServer(data)
        connect(window = 0)

        assertEquals(0, receiveUntilQuiet())
        val before = segments().size

        // not yet: the data has not waited long enough
        TcpConnection.sweepStaleConnections(windowProbeAfterMs = 60_000)
        assertEquals(before, segments().size)

        TcpConnection.sweepStaleConnections(windowProbeAfterMs = 0)
        val probe = segments().drop(before).single()
        assertTrue(probe.header.ack && !probe.header.fin && !probe.header.rst)
        assertEquals(0, probe.payload?.length() ?: 0)
        assertEquals("the probe sits one below the next sequence number", ackNumber - 1, probe.header.sequenceNumber)
        nextSegmentIndex++

        // the device answers the probe with its window, which has opened in the meantime
        while (finSeen == null) {
            ack(window = 65535)
            awaitUntil("the data never arrived") { receive() > 0 || finSeen != null }
        }
        assertArrayEquals(data, received.toByteArray())
    }

    companion object {
        private const val LOCAL_PORT = 47200
    }
}
