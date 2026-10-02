package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection.TransportLayerState
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for docs/vpn-mitm-audit.md PKT-38: a connection's byte counters used to be written to
 * the database once per data segment. A large upload queued thousands of writes, and the next
 * new connection then blocked the packet thread behind them for seconds.
 */
class ByteCounterBatchingTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var serverThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var dbConnector: RecordingDatabaseConnector
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var connection: TransportLayerConnection

    private val acceptedSocket = AtomicReference<Socket?>(null)
    private val bytesSeenByServer = AtomicLong(0)

    private val localAddr = InetAddress.getByName("10.0.0.90") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private var deviceSeq = 1

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        serverSocket = ServerSocket(0, 1, remoteAddr)
        serverThread = Thread {
            try {
                val socket = serverSocket.accept()
                acceptedSocket.set(socket)
                val buf = ByteArray(65536)
                while (true) {
                    val n = socket.getInputStream().read(buf)
                    if (n < 0) break
                    bytesSeenByServer.addAndGet(n.toLong())
                }
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        serverThread.start()

        dbConnector = RecordingDatabaseConnector()
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir(), databaseConnector = dbConnector)
        pump = SelectorPump(componentManager.selector)
        pump.start()
        deviceWriter = RecordingDeviceWriter()

        val syn = PacketFixtures.buildTcpSynPacket(localAddr, LOCAL_PORT, remoteAddr, serverSocket.localPort)
        connection = TransportLayerConnection.getInstance(syn, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(syn.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        sendFromDevice(ByteArray(0))
        assertEquals(TransportLayerState.CONNECTED, connection.state)
    }

    @After
    fun teardown() {
        pump.stop()
        acceptedSocket.get()?.close()
        serverSocket.close()
        serverThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    private fun sendFromDevice(payload: ByteArray) {
        val packet = PacketFixtures.buildTcpDataPacket(
            localAddr, LOCAL_PORT, remoteAddr, serverSocket.localPort,
            seq = deviceSeq, ack = 1, payload = payload, pshFlag = payload.isNotEmpty()
        )
        deviceSeq += payload.size
        connection.unwrapOutbound(packet.payload)
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 5000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !condition()) {
            Thread.sleep(10)
        }
        assertTrue(message, condition())
    }

    private fun row() = dbConnector.connections.single()

    @Test
    fun `many outbound segments cause one counter update per flush, not one per segment`() {
        val segments = 500
        val segment = ByteArray(1000) { 0x42 }

        repeat(segments) { sendFromDevice(segment) }
        awaitUntil("the server should have received every segment") { bytesSeenByServer.get() == segments * 1000L }

        // nothing has been written yet, however many segments went through
        Thread.sleep(200)
        assertEquals("no database write may happen per segment", 0, dbConnector.byteCounterUpdates.get())
        assertEquals(0L, row().bytesOut)

        runBlocking { connection.flushByteCounters() }

        assertEquals("one flush writes one update", 1, dbConnector.byteCounterUpdates.get())
        assertEquals(segments * 1000L, row().bytesOut)

        // a flush with nothing new to report writes nothing
        runBlocking { connection.flushByteCounters() }
        assertEquals(1, dbConnector.byteCounterUpdates.get())
    }

    @Test
    fun `bytes recorded between flushes are added up, in both directions`() {
        sendFromDevice(ByteArray(300))
        awaitUntil("the server should have received the request") { bytesSeenByServer.get() == 300L }
        runBlocking { connection.flushByteCounters() }
        assertEquals(300L, row().bytesOut)

        // the server answers; inbound bytes are counted the same way
        val messagesBefore = deviceWriter.sentMessages.size
        acceptedSocket.get()!!.getOutputStream().apply { write(ByteArray(700)); flush() }
        awaitUntil("the reply should have been passed on to the device") { deviceWriter.sentMessages.size > messagesBefore }
        sendFromDevice(ByteArray(50))
        awaitUntil("the server should have received the second request") { bytesSeenByServer.get() == 350L }

        runBlocking { connection.flushByteCounters() }

        assertEquals(350L, row().bytesOut)
        assertEquals(700L, row().bytesIn)
    }

    @Test
    fun `closing a connection writes what it had not flushed yet`() {
        sendFromDevice(ByteArray(1234))
        awaitUntil("the server should have received the data") { bytesSeenByServer.get() == 1234L }
        assertEquals(0L, row().bytesOut)

        connection.closeHard()

        // the connection leaves the cache, so no periodic flush would reach it any more
        awaitUntil("the unflushed bytes must be written when the connection is closed") { row().bytesOut == 1234L }
    }

    companion object {
        private const val LOCAL_PORT = 49001
    }
}
