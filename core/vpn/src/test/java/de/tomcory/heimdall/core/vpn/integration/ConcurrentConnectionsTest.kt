package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
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
}
