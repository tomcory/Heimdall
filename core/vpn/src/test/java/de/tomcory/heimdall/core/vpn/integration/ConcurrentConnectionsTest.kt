package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TcpConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Opens many TcpConnections concurrently against a real local TCP server to exercise
 * ConnectionCache (a process-wide singleton backed by a ConcurrentHashMap) under genuine
 * concurrent load, rather than in isolation as the unit tests do.
 */
class ConcurrentConnectionsTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var acceptThread: Thread
    private lateinit var pump: SelectorPump

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        serverSocket = ServerSocket(0, 256, InetAddress.getByName("127.0.0.1"))
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        if (::serverSocket.isInitialized && !serverSocket.isClosed) serverSocket.close()
        if (::acceptThread.isInitialized) acceptThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    @Test
    fun `N concurrent TCP connections are all tracked without loss or corruption`() {
        val n = 50
        val accepted = CopyOnWriteArrayList<java.net.Socket>()

        acceptThread = Thread {
            try {
                while (!serverSocket.isClosed) {
                    val socket = serverSocket.accept()
                    accepted.add(socket)
                }
            } catch (e: Exception) {
                // server socket closed during teardown, expected
            }
        }
        acceptThread.start()

        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        pump = SelectorPump(componentManager.selector)
        pump.start()

        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.9") as Inet4Address
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val executor = Executors.newFixedThreadPool(16)
        val latch = CountDownLatch(n)
        val connections = CopyOnWriteArrayList<TransportLayerConnection>()
        val errors = CopyOnWriteArrayList<Throwable>()

        for (i in 0 until n) {
            executor.submit {
                try {
                    val localPort = 40000 + i
                    val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
                    val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
                    connection?.unwrapOutbound(synPacket.payload)
                    connection?.let { connections.add(it) }
                } catch (e: Throwable) {
                    errors.add(e)
                } finally {
                    latch.countDown()
                }
            }
        }

        assertTrue("connections did not complete in time", latch.await(20, TimeUnit.SECONDS))
        executor.shutdown()

        assertTrue("unexpected errors during concurrent connection setup: $errors", errors.isEmpty())
        assertEquals(n, connections.size)
        assertEquals("every connection must be tracked under a distinct local port", n, connections.map { it.localPort }.distinct().size)

        // wait for the real handshakes (driven by the selector pump) to complete and SYN-ACKs to be written back
        val deadline = System.currentTimeMillis() + 10000
        while (System.currentTimeMillis() < deadline && deviceWriter.sentMessages.size < n) {
            Thread.sleep(20)
        }
        assertEquals("every connection should have produced exactly one SYN-ACK", n, deviceWriter.sentMessages.size)
    }

    /**
     * Regression test for docs/vpn-mitm-audit.md PKT-16 (V-25): `TcpConnection.ourSeqNum`/
     * `theirSeqNum` used to be plain non-atomic `Long` fields advanced via `+=`, mutated from both
     * the InboundTrafficHandler-driven data path (`wrapInbound`) and the OutboundTrafficHandler-
     * driven path (`handleAckData`/`handleFin`) for the same connection - a genuine concurrent
     * read-modify-write hazard that can silently lose increments.
     *
     * This drives `increaseOurSeqNum`/`increaseTheirSeqNum` (private - accessed via reflection,
     * exactly like [de.tomcory.heimdall.core.vpn.connection.transportLayer.TcpConnectionSequenceNumberTest])
     * concurrently from many threads on both counters at once and asserts the final values reflect
     * every increment, with none lost to a race. Reflection is used instead of driving the full
     * `unwrapOutbound`/`unwrapInbound` call chain so the test isolates the counter race itself,
     * without dragging the encryption/app-layer stack (TLS/HTTP sniffing on synthetic payloads)
     * into what should be a narrowly-scoped concurrency test.
     */
    @Test
    fun `concurrent increments of ourSeqNum and theirSeqNum from both directions never lose an update`() {
        acceptThread = Thread {
            try {
                serverSocket.accept()
            } catch (e: Exception) {
                // server socket closed during teardown, expected
            }
        }
        acceptThread.start()

        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        pump = SelectorPump(componentManager.selector)
        pump.start()

        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.10") as Inet4Address
        val localPort = 42000
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = serverSocket.localPort

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, remotePort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        assertTrue("expected a TcpConnection to be created", connection is TcpConnection)
        connection!!.unwrapOutbound(synPacket.payload)

        val handshakeDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < handshakeDeadline && deviceWriter.sentMessages.isEmpty()) {
            Thread.sleep(20)
        }
        assertTrue("expected a SYN-ACK to be sent back to the device", deviceWriter.sentMessages.isNotEmpty())

        val ackPacket = PacketFixtures.buildTcpDataPacket(
            localAddr = localAddr, localPort = localPort, remoteAddr = remoteAddr, remotePort = remotePort,
            seq = 1, ack = 1, payload = ByteArray(0), pshFlag = false
        )
        connection.unwrapOutbound(ackPacket.payload)
        assertEquals(TransportLayerConnection.TransportLayerState.CONNECTED, connection.state)

        val increaseOurSeqNum = TcpConnection::class.java.getDeclaredMethod("increaseOurSeqNum", Int::class.java)
        increaseOurSeqNum.isAccessible = true
        val increaseTheirSeqNum = TcpConnection::class.java.getDeclaredMethod("increaseTheirSeqNum", Int::class.java)
        increaseTheirSeqNum.isAccessible = true
        val ourSeqNumField = TcpConnection::class.java.getDeclaredField("ourSeqNum")
        ourSeqNumField.isAccessible = true
        val theirSeqNumField = TcpConnection::class.java.getDeclaredField("theirSeqNum")
        theirSeqNumField.isAccessible = true

        fun readOurSeqNum() = (ourSeqNumField.get(connection) as AtomicLong).get()
        fun readTheirSeqNum() = (theirSeqNumField.get(connection) as AtomicLong).get()

        val ourSeqNumBefore = readOurSeqNum()
        val theirSeqNumBefore = readTheirSeqNum()

        val threadsPerDirection = 8
        val incrementsPerThread = 2000
        val incrementSize = 7

        val executor = Executors.newFixedThreadPool(threadsPerDirection * 2)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadsPerDirection * 2)
        val errors = CopyOnWriteArrayList<Throwable>()

        repeat(threadsPerDirection) {
            executor.submit {
                try {
                    startLatch.await()
                    repeat(incrementsPerThread) {
                        increaseOurSeqNum.invoke(connection, incrementSize)
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                } finally {
                    doneLatch.countDown()
                }
            }
            executor.submit {
                try {
                    startLatch.await()
                    repeat(incrementsPerThread) {
                        increaseTheirSeqNum.invoke(connection, incrementSize)
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue("stress operations did not complete in time", doneLatch.await(30, TimeUnit.SECONDS))
        executor.shutdown()
        assertTrue("unexpected errors during concurrent increments: $errors", errors.isEmpty())

        val expectedIncrease = threadsPerDirection.toLong() * incrementsPerThread * incrementSize

        assertEquals(
            "ourSeqNum must reflect every increment, with none lost to a concurrent update",
            ourSeqNumBefore + expectedIncrease,
            readOurSeqNum()
        )
        assertEquals(
            "theirSeqNum must reflect every increment, with none lost to a concurrent update",
            theirSeqNumBefore + expectedIncrease,
            readTheirSeqNum()
        )
    }
}
