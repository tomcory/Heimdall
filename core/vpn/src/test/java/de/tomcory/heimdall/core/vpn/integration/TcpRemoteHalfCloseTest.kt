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
import java.nio.channels.SocketChannel
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for docs/records/vpn-mitm-audit.md PKT-53 (V-59): a FIN from the remote host only says that it
 * has finished sending. Data the device sends afterwards must still reach the remote host, and
 * must not be answered with a reset.
 *
 * The device side here sends only what the window it was last told allows, like a real TCP stack.
 */
class TcpRemoteHalfCloseTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var serverThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var connection: TransportLayerConnection

    private val acceptedSocket = AtomicReference<Socket?>(null)
    private val receivedByServer = AtomicReference<ByteArray?>(null)

    private val localAddr = InetAddress.getByName("10.0.0.96") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private var localPort = 0

    // the fake device's view of the connection
    private var deviceSeq = 1
    private var nextSegmentIndex = 0
    private var acknowledged = 1
    private var window = 0
    private val sent = ByteArrayOutputStream()

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

    /** Runs [behaviour] on the server's side of the connection once it is accepted. */
    private fun startServer(behaviour: (Socket) -> Unit) {
        serverThread = Thread {
            try {
                val socket = serverSocket.accept()
                acceptedSocket.set(socket)
                behaviour(socket)
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        serverThread.start()
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 10000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(10)
        }
        fail(message)
    }

    private fun segments(): List<TcpPacket> = deviceWriter.sentMessages.map { (it.obj as IpPacket).payload as TcpPacket }

    private fun resets() = segments().count { it.header.rst }

    /** The next sequence number the VPN will use, i.e. what the device acknowledges once it has everything. */
    private fun vpnNext(): Int = segments().maxOf {
        it.header.sequenceNumber + (it.payload?.length() ?: 0) + (if (it.header.fin || it.header.syn) 1 else 0)
    }

    /** Takes in what the VPN has sent to the device since the last call: acknowledgement number and window. */
    private fun takeInAcks() {
        val all = segments()
        while (nextSegmentIndex < all.size) {
            val segment = all[nextSegmentIndex++]
            if (segment.header.ack) {
                acknowledged = segment.header.acknowledgmentNumber
                window = segment.header.windowAsInt
            }
        }
    }

    private fun connect(port: Int) {
        localPort = port
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, serverSocket.localPort)
        connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        takeInAcks()
        sendFromDevice(ByteArray(0))
        // the remote host may already have closed its side by now
        assertTrue(connection.state == TransportLayerState.CONNECTED || connection.state == TransportLayerState.CLOSING)
    }

    private fun sendFromDevice(payload: ByteArray, finFlag: Boolean = false) {
        val packet = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = deviceSeq, ack = vpnNext(), payload = payload, finFlag = finFlag, pshFlag = payload.isNotEmpty()
        )
        connection.unwrapOutbound(packet.payload)
    }

    private fun chunk(index: Int) = ByteArray(SEGMENT_SIZE) { (index * 11 + it).toByte() }

    /**
     * Sends [total] bytes the way a device would, never beyond the window it was last told.
     * Stops early, without failing, when the window stays shut for [giveUpAfterMs].
     */
    private fun sendData(total: Int, giveUpAfterMs: Long = 30_000) {
        var index = 0
        var shutSince = 0L
        while (sent.size() < total) {
            takeInAcks()
            val usable = acknowledged + window - deviceSeq
            if (usable <= 0) {
                if (shutSince == 0L) shutSince = System.currentTimeMillis()
                if (System.currentTimeMillis() - shutSince > giveUpAfterMs) return
                Thread.sleep(5)
                continue
            }
            shutSince = 0L
            val payload = chunk(index++).copyOf(minOf(SEGMENT_SIZE, usable, total - sent.size()))
            sendFromDevice(payload)
            sent.write(payload)
            deviceSeq += payload.size
        }
    }

    private fun isChannelOpen(): Boolean {
        val field = TcpConnection::class.java.getDeclaredField("selectableChannel")
        field.isAccessible = true
        return (field.get(connection) as SocketChannel).isOpen
    }

    @Test
    fun `data the device sends after the remote host's FIN reaches the remote host`() {
        startServer { socket ->
            socket.getOutputStream().write("HELLO\n".toByteArray())
            socket.shutdownOutput()
            receivedByServer.set(socket.getInputStream().readBytes())
            socket.close()
        }
        connect(47400)

        awaitUntil("the remote host's FIN never reached the device") { segments().any { it.header.fin } }
        assertEquals(TransportLayerState.CLOSING, connection.state)

        sendData(200_000)
        sendFromDevice(ByteArray(0), finFlag = true)
        deviceSeq++

        awaitUntil("the remote host never saw the end of the stream", timeoutMs = 30000) { receivedByServer.get() != null }
        assertArrayEquals("the remote host must receive everything the device sent after its FIN", sent.toByteArray(), receivedByServer.get())
        assertEquals("nothing may be answered with a reset", 0, resets())
        awaitUntil("the close must complete once both sides are done") { connection.state == TransportLayerState.CLOSED }
        assertFalse(isChannelOpen())
    }

    @Test
    fun `data for a remote host that has closed its socket completely draws a reset`() {
        startServer { socket -> socket.close() }
        connect(47401)
        awaitUntil("the remote host's FIN never reached the device") { segments().any { it.header.fin } }

        // the first write after the close is taken by the kernel; the remote host answers it
        // with a reset, and the next write fails
        awaitUntil("the device never learned that its data cannot be delivered") {
            if (connection.state == TransportLayerState.CLOSING) {
                sendFromDevice(chunk(0).copyOf(100))
                deviceSeq += 100
            }
            resets() > 0
        }
        assertFalse(isChannelOpen())
    }

    @Test
    fun `data still queued for the remote host when it closes its side is not lost`() {
        val windowShut = CountDownLatch(1)
        val mayRead = CountDownLatch(1)
        startServer { socket ->
            windowShut.await()
            socket.shutdownOutput()
            mayRead.await()
            receivedByServer.set(socket.getInputStream().readBytes())
            socket.close()
        }
        connect(47402)

        // the remote host reads nothing, so data piles up on its way out until the window shuts
        sendData(64 * 1024 * 1024, giveUpAfterMs = 1000)
        assertTrue("the window must have shut with data queued", sent.size() > 0)
        windowShut.countDown()
        awaitUntil("the remote host's FIN never reached the device") { segments().any { it.header.fin } }
        assertTrue("the channel must stay open while data is queued for it", isChannelOpen())

        // the device closes while its data is still queued: the channel is closed only after it
        sendFromDevice(ByteArray(0), finFlag = true)
        deviceSeq++
        assertEquals("the connection must stay until the queued data has been written", TransportLayerState.CLOSING, connection.state)
        assertTrue(isChannelOpen())

        mayRead.countDown()
        awaitUntil("the remote host never saw the end of the stream", timeoutMs = 30000) { receivedByServer.get() != null }
        assertArrayEquals("nothing queued for the remote host may be lost", sent.toByteArray(), receivedByServer.get())
        assertEquals(0, resets())
        awaitUntil("the connection must end once the data is out") { connection.state == TransportLayerState.CLOSED }
        assertFalse(isChannelOpen())
    }

    @Test
    fun `data after the device's own FIN still aborts a connection the remote host closed first`() {
        startServer { socket ->
            socket.shutdownOutput()
            receivedByServer.set(socket.getInputStream().readBytes())
        }
        connect(47403)
        awaitUntil("the remote host's FIN never reached the device") { segments().any { it.header.fin } }

        sendFromDevice(ByteArray(0), finFlag = true)
        deviceSeq++
        sendFromDevice("too late".toByteArray())

        assertEquals("data after the device's FIN is a protocol violation", 1, resets())
    }

    companion object {
        private const val SEGMENT_SIZE = 8000
    }
}
