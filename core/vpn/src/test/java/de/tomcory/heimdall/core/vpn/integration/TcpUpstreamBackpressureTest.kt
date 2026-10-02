package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
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
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

/**
 * Tests for docs/vpn-mitm-audit.md PKT-43 (V-50): a remote host that takes data slowly must slow
 * the app down, not the thread that handles every packet from the device. Data the outward-facing
 * channel does not take is queued, and the receive window advertised to the device shrinks with
 * the room that is left.
 *
 * The device side here sends only what the window it was last told allows, like a real TCP stack.
 */
class TcpUpstreamBackpressureTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var serverThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var connection: TransportLayerConnection

    private val acceptedSocket = AtomicReference<Socket?>(null)

    /** The server reads nothing until this is released. */
    private val serverMayRead = CountDownLatch(1)
    private val receivedByServer = AtomicReference<ByteArray?>(null)

    private val localAddr = InetAddress.getByName("10.0.0.95") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

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

        serverThread = Thread {
            try {
                val socket = serverSocket.accept()
                acceptedSocket.set(socket)
                serverMayRead.await()
                receivedByServer.set(socket.getInputStream().readBytes())
                socket.close()
            } catch (e: Exception) {
                // closed during teardown
            }
        }
        serverThread.start()
    }

    @After
    fun teardown() {
        serverMayRead.countDown()
        if (::pump.isInitialized) pump.stop()
        acceptedSocket.get()?.close()
        if (!serverSocket.isClosed) serverSocket.close()
        if (::serverThread.isInitialized) serverThread.join(2000)
        ConnectionCache.closeAllAndClear()
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

    /** Takes in what the VPN has sent to the device since the last call: acknowledgement number and window. */
    private fun takeInAcks() {
        val all = segments()
        while (nextSegmentIndex < all.size) {
            val segment = all[nextSegmentIndex++]
            assertFalse("the connection must not be reset", segment.header.rst)
            if (segment.header.ack) {
                acknowledged = segment.header.acknowledgmentNumber
                window = segment.header.windowAsInt
            }
        }
    }

    private fun connect() {
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, LOCAL_PORT, remoteAddr, serverSocket.localPort)
        connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        awaitUntil("expected a SYN-ACK") { deviceWriter.sentMessages.isNotEmpty() }
        ourSeqAfterSyn = segments().first().header.sequenceNumber + 1
        takeInAcks()
        sendFromDevice(ByteArray(0))
        assertEquals(TransportLayerState.CONNECTED, connection.state)
    }

    private var ourSeqAfterSyn = 0

    /** Sends a segment from the device and returns how long the VPN took to handle it. */
    private fun sendFromDevice(payload: ByteArray, finFlag: Boolean = false, seq: Int = deviceSeq): Long {
        val packet = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = LOCAL_PORT, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = seq, ack = ourSeqAfterSyn, payload = payload, finFlag = finFlag
        )
        val startedAt = System.nanoTime()
        connection.unwrapOutbound(packet.payload)
        return (System.nanoTime() - startedAt) / 1_000_000
    }

    private fun chunk(index: Int) = ByteArray(SEGMENT_SIZE) { (index * 7 + it).toByte() }

    /**
     * Sends data the way a device would, never beyond the window it was last told, until that
     * window is shut.
     *
     * @return the longest time a single segment took to be handled, in ms.
     */
    private fun sendUntilWindowIsShut(): Long {
        var slowest = 0L
        var index = 0
        val deadline = System.currentTimeMillis() + 60_000
        while (System.currentTimeMillis() < deadline) {
            takeInAcks()
            val usable = acknowledged + window - deviceSeq
            if (window == 0 && usable <= 0) {
                return slowest
            }
            if (usable < SEGMENT_SIZE) {
                // a real device would wait for the window to open further; here it never
                // does on its own, so the leftover is used up with a smaller segment
                if (usable <= 0) {
                    Thread.sleep(5)
                    continue
                }
            }
            val payload = chunk(index++).copyOf(minOf(SEGMENT_SIZE, usable))
            slowest = maxOf(slowest, sendFromDevice(payload))
            sent.write(payload)
            deviceSeq += payload.size
            assertTrue("the device must not be able to send without bound to a remote host that reads nothing", sent.size() < 64 * 1024 * 1024)
        }
        fail("the advertised window never went to zero (sent ${sent.size()} bytes)")
        return slowest
    }

    @Test
    fun `a remote host that reads nothing shuts the window instead of blocking the packet thread`() {
        connect()

        val slowest = sendUntilWindowIsShut()
        assertTrue("handling a segment took $slowest ms while the remote host read nothing", slowest < 1000)
        assertTrue("some data must have been accepted before the window shut", sent.size() > 0)
        assertEquals("everything sent inside the window must have been acknowledged", deviceSeq, acknowledged)

        // a segment sent into the shut window is not taken: the acknowledgement does not move
        val before = segments().size
        sendFromDevice(chunk(0))
        takeInAcks()
        assertEquals(deviceSeq, acknowledged)
        assertEquals(0, window)
        assertEquals("the segment must be answered with an ACK", before + 1, segments().size)

        // the remote host starts reading: the device is told that the window has opened
        serverMayRead.countDown()
        awaitUntil("the device was never told that the window opened") {
            takeInAcks()
            window > 0
        }

        // the device finishes with a little more data and closes its sending side
        val tail = "the end".toByteArray()
        sendFromDevice(tail)
        sent.write(tail)
        deviceSeq += tail.size
        sendFromDevice(ByteArray(0), finFlag = true)

        // the remote host sees the end of the stream only after everything before it
        awaitUntil("the remote host never saw the end of the stream", timeoutMs = 30000) { receivedByServer.get() != null }
        assertArrayEquals("the remote host must have received exactly what the device sent", sent.toByteArray(), receivedByServer.get())
    }

    @Test
    fun `a close from the device waits for the data that is still on its way out`() {
        connect()
        // like a MitM'd TLS connection: the device's FIN closes the whole connection
        val field = TransportLayerConnection::class.java.getDeclaredField("encryptionLayer")
        field.isAccessible = true
        field.set(connection, ForwardingNoHalfCloseLayer(connection, componentManager))

        sendUntilWindowIsShut()

        sendFromDevice(ByteArray(0), finFlag = true)
        assertEquals(TransportLayerState.CLOSING, connection.state)
        takeInAcks()
        assertEquals("the device's FIN must be acknowledged", deviceSeq + 1, acknowledged)
        val ourFin = segments().last { it.header.fin }

        // the device acknowledges our FIN: the handshake is complete, but data is still queued
        val finalAck = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = LOCAL_PORT, remoteAddr = remoteAddr, remotePort = serverSocket.localPort,
            seq = deviceSeq + 1, ack = ourFin.header.sequenceNumber + 1
        )
        connection.unwrapOutbound(finalAck.payload)
        assertEquals("the connection must stay until the queued data has been written", TransportLayerState.CLOSING, connection.state)

        serverMayRead.countDown()
        awaitUntil("the remote host never saw the end of the stream", timeoutMs = 30000) { receivedByServer.get() != null }
        assertArrayEquals("nothing the device sent before closing may be lost", sent.toByteArray(), receivedByServer.get())
        awaitUntil("the connection must end once the data is out") { connection.state == TransportLayerState.CLOSED }
    }

    /** Passes data straight through and cannot carry a half-close, like a MitM'd TLS connection. */
    private class ForwardingNoHalfCloseLayer(
        private val transport: TransportLayerConnection,
        componentManager: ComponentManager
    ) : EncryptionLayerConnection(0, transport, componentManager) {
        override val protocol = "TEST"
        override val supportsHalfClose = false
        override fun unwrapOutbound(payload: ByteArray) = transport.wrapOutbound(payload)
        override fun unwrapOutbound(packet: Packet) = transport.wrapOutbound(packet.rawData)
        override fun unwrapInbound(payload: ByteArray) = transport.wrapInbound(payload)
        override fun wrapOutbound(payload: ByteArray) = transport.wrapOutbound(payload)
        override fun wrapInbound(payload: ByteArray) = transport.wrapInbound(payload)
    }

    companion object {
        private const val LOCAL_PORT = 47300
        private const val SEGMENT_SIZE = 8000
    }
}
