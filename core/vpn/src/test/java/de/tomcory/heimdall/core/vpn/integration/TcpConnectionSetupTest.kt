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
import io.mockk.every
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Tests for docs/vpn-mitm-audit.md PKT-41 (V-51): the blocking parts of setting up a TCP
 * connection (finding the owning app, protecting and connecting the socket) must not run on the
 * thread that creates the connection, which is the one that handles every packet from the device.
 */
class TcpConnectionSetupTest {

    private lateinit var serverSocket: ServerSocket
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var deviceWriter: RecordingDeviceWriter
    private lateinit var dbConnector: RecordingDatabaseConnector

    private val accepted = CopyOnWriteArrayList<Socket>()

    /** Holds the app lookup back, standing in for a slow binder call. */
    private val appLookupGate = CountDownLatch(1)

    private val localAddr = InetAddress.getByName("10.0.0.70") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        serverSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        Thread {
            try {
                while (true) accepted.add(serverSocket.accept())
            } catch (e: Exception) {
                // closed during teardown
            }
        }.apply { isDaemon = true }.start()

        dbConnector = RecordingDatabaseConnector()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        // stubbed on the fixture's AppFinder itself: a chained stub would replace it with a new mock
        val appFinder = componentManager.appFinder
        every { appFinder.getAppId(any(), any(), any(), any(), any()) } answers {
            appLookupGate.await(10, TimeUnit.SECONDS)
            1000
        }
        pump = SelectorPump(componentManager.selector)
        pump.start()
        deviceWriter = RecordingDeviceWriter()
    }

    @After
    fun teardown() {
        appLookupGate.countDown()
        if (::pump.isInitialized) pump.stop()
        accepted.forEach { it.close() }
        if (!serverSocket.isClosed) serverSocket.close()
        ConnectionCache.closeAllAndClear()
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 5000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !condition()) {
            Thread.sleep(20)
        }
        assertTrue(message, condition())
    }

    private fun open(localPort: Int): TransportLayerConnection {
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, serverSocket.localPort)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(synPacket.payload)
        return connection
    }

    @Test
    fun `creating connections does not wait for the app lookup`() {
        val startedAt = System.currentTimeMillis()
        val connections = (0 until 20).map { open(46000 + it) }
        val elapsed = System.currentTimeMillis() - startedAt

        // the lookup is still blocked for every one of them
        assertTrue("creating 20 connections took $elapsed ms while the app lookup was blocked", elapsed < 2000)
        assertTrue(connections.all { it.state == TransportLayerState.CONNECTING })
        assertTrue("no connection may be stored before its app is known", dbConnector.connections.isEmpty())
        assertTrue(deviceWriter.sentMessages.isEmpty())

        appLookupGate.countDown()

        awaitUntil("every connection must be answered with a SYN-ACK once it is set up") {
            deviceWriter.sentMessages.count { ((it.obj as IpPacket).payload as TcpPacket).header.let { h -> h.syn && h.ack } } == 20
        }
        assertEquals(20, dbConnector.connections.size)
        assertEquals(setOf(1000), dbConnector.connections.map { it.initiatorId }.toSet())
        assertEquals(setOf("com.example.test"), dbConnector.connections.map { it.initiatorPkg }.toSet())
    }

    @Test
    fun `a reset from the device during setup ends the connection without a trace`() {
        val localPort = 46100
        val connection = open(localPort)

        // the client gives up while the connection is still being set up
        val rst = PacketFixtures.buildTcpDataPacket(localAddr, localPort, remoteAddr, serverSocket.localPort, seq = 1, ack = 0, ackFlag = false, rstFlag = true)
        connection.unwrapOutbound(rst.payload)
        assertEquals(TransportLayerState.CLOSED, connection.state)

        appLookupGate.countDown()
        Thread.sleep(500)

        assertTrue("a connection that was reset during setup must not be stored", dbConnector.connections.isEmpty())
        assertTrue("nothing may be sent to a device that has reset the connection", deviceWriter.sentMessages.isEmpty())
        assertTrue("the outward-facing socket must not have been connected", accepted.isEmpty())
        assertEquals(TransportLayerState.CLOSED, connection.state)
    }
}
