package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.FakeClientTlsDriver
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.QuicInitialFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import de.tomcory.heimdall.core.vpn.rules.BlockList
import de.tomcory.heimdall.core.vpn.rules.BlockReason
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Connections to hosts on the block list are dropped: at once if the name is known from the DNS
 * cache or the address itself is listed, and as soon as the server name is read otherwise. No
 * payload reaches a blocked host, and the connection's row says why.
 */
class HostBlockingTest {

    private lateinit var tcpServer: ServerSocket
    private lateinit var udpServer: DatagramSocket
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var dbConnector: RecordingDatabaseConnector
    private lateinit var deviceWriter: RecordingDeviceWriter
    private val accepted = CopyOnWriteArrayList<Socket>()

    private val localAddr = InetAddress.getByName("10.0.0.61") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private var nextPort = 47000

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        tcpServer = ServerSocket(0, 50, remoteAddr)
        Thread {
            try {
                while (true) accepted.add(tcpServer.accept())
            } catch (e: Exception) {
                // closed during teardown
            }
        }.apply { isDaemon = true }.start()
        udpServer = DatagramSocket(0, remoteAddr).apply { soTimeout = 400 }
        deviceWriter = RecordingDeviceWriter()
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        accepted.forEach { it.close() }
        tcpServer.close()
        udpServer.close()
        ConnectionCache.closeAllAndClear()
    }

    /** @param dnsName The name the DNS cache holds for the server's address, if any. */
    private fun start(blocked: List<String>, dnsName: String? = null) {
        dbConnector = RecordingDatabaseConnector()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(), databaseConnector = dbConnector, blockList = BlockList(blocked)
        )
        dnsName?.let { componentManager.dnsCache.put(remoteAddr.hostAddress!!, it) }
        pump = SelectorPump(componentManager.selector)
        pump.start()
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 5000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && !condition()) {
            Thread.sleep(20)
        }
        assertTrue(message, condition())
    }

    private fun tcpSegments(): List<TcpPacket> =
        deviceWriter.sentMessages.filter { it.what == DeviceWriteThread.WRITE_TCP }.map { (it.obj as IpPacket).payload as TcpPacket }

    private fun icmpErrors() = deviceWriter.sentMessages.filter { it.what == DeviceWriteThread.WRITE_ICMP }

    private fun openTcp(localPort: Int = nextPort++): TransportLayerConnection {
        val syn = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, tcpServer.localPort)
        val connection = TransportLayerConnection.getInstance(syn, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(syn.payload)
        return connection
    }

    private fun sendUdp(payload: ByteArray, localPort: Int): TransportLayerConnection {
        val packet = PacketFixtures.buildUdpPacket(localAddr, localPort, remoteAddr, udpServer.localPort, payload)
        val connection = TransportLayerConnection.getInstance(packet, componentManager, deviceWriter.handler)!!
        connection.unwrapOutbound(packet.payload)
        return connection
    }

    private fun receivedAtUdpServer(): Int {
        var count = 0
        while (true) {
            try {
                udpServer.receive(DatagramPacket(ByteArray(2048), 2048))
                count++
            } catch (e: SocketTimeoutException) {
                return count
            }
        }
    }

    private fun assertBlockedByRule(connection: TransportLayerConnection) {
        assertTrue(connection.blockedByRule)
        awaitUntil("the block must be recorded") { dbConnector.connections.singleOrNull()?.blocked == true }
        assertEquals(BlockReason.HOST_RULE, dbConnector.connections.single().blockReason)
    }

    @Test
    fun `a TCP connection to a host the DNS cache names is refused before any socket is opened`() {
        start(blocked = listOf("tracker.example"), dnsName = "cdn.tracker.example")
        val connection = openTcp()

        awaitUntil("the SYN must be answered with a reset") { tcpSegments().any { it.header.rst } }
        assertFalse("no SYN-ACK may be sent", tcpSegments().any { it.header.syn })
        assertBlockedByRule(connection)
        Thread.sleep(200)
        assertTrue("no connection may reach the host", accepted.isEmpty())
        assertNull("a refused connection does not stay in the cache", ConnectionCache.allConnections().firstOrNull())
    }

    @Test
    fun `an address on the list is blocked without a name`() {
        start(blocked = listOf(remoteAddr.hostAddress!!))
        val connection = openTcp()

        awaitUntil("the SYN must be answered with a reset") { tcpSegments().any { it.header.rst } }
        assertBlockedByRule(connection)
        assertTrue(accepted.isEmpty())
    }

    @Test
    fun `other hosts connect as before while a block list is set`() {
        start(blocked = listOf("tracker.example"), dnsName = "api.example.org")
        val connection = openTcp()

        awaitUntil("the connection must be established") { tcpSegments().any { it.header.syn && it.header.ack } }
        assertFalse(connection.blockedByRule)
        awaitUntil("the host must see the connection") { accepted.size == 1 }
        assertFalse(dbConnector.connections.single().blocked)
        assertNull(dbConnector.connections.single().blockReason)
    }

    @Test
    fun `a TLS connection is dropped when its server name is on the list, and the ClientHello is not forwarded`() {
        // no name in the DNS cache: only the ClientHello says where the connection goes
        start(blocked = listOf("tracker.example"))
        val localPort = nextPort++
        val connection = openTcp(localPort)
        awaitUntil("the connection must be established first") { tcpSegments().any { it.header.syn && it.header.ack } }
        awaitUntil("the host sees the TCP connection") { accepted.size == 1 }
        connection.unwrapOutbound(
            PacketFixtures.buildTcpDataPacket(localAddr, localPort, remoteAddr, tcpServer.localPort, seq = 1, ack = 1, pshFlag = false).payload
        )

        val clientHello = FakeClientTlsDriver("eu.tracker.example", tcpServer.localPort).wrap()!!
        connection.unwrapOutbound(
            PacketFixtures.buildTcpDataPacket(localAddr, localPort, remoteAddr, tcpServer.localPort, seq = 1, ack = 1, payload = clientHello).payload
        )

        awaitUntil("the device must be told with a reset") { tcpSegments().any { it.header.rst } }
        assertBlockedByRule(connection)
        // the host's side of the socket is closed without a single byte having arrived
        val upstream = accepted.single().apply { soTimeout = 2000 }
        assertEquals("the ClientHello must not reach the host", -1, upstream.getInputStream().read())
        assertEquals("eu.tracker.example", dbConnector.connections.single().remoteHost)
    }

    @Test
    fun `a UDP flow to a blocked host is dropped, answered with ICMP errors and recorded once`() {
        start(blocked = listOf("tracker.example"), dnsName = "tracker.example")
        val localPort = nextPort++
        val connection = sendUdp(byteArrayOf(1, 2, 3), localPort)
        repeat(4) { assertTrue("further datagrams must reach the same connection", sendUdp(byteArrayOf(4, 5, 6), localPort) === connection) }

        assertEquals("nothing may reach the host", 0, receivedAtUdpServer())
        assertEquals("only the first few datagrams are answered", 3, icmpErrors().size)
        assertBlockedByRule(connection)
    }

    @Test
    fun `a QUIC flow is held until its server name is read, and dropped if the name is on the list`() {
        start(blocked = listOf("tracker.example"))
        val localPort = nextPort++
        val datagrams = QuicInitialFixtures.clientInitialDatagrams(QuicInitialFixtures.clientHello("h3.tracker.example", listOf("h3")), datagrams = 1, shuffle = false)
        val connection = datagrams.map { sendUdp(it, localPort) }.last()

        assertEquals("nothing may reach the host", 0, receivedAtUdpServer())
        assertTrue(icmpErrors().isNotEmpty())
        assertBlockedByRule(connection)
        sendUdp(byteArrayOf(7, 7, 7), localPort)
        assertEquals("later datagrams are dropped as well", 0, receivedAtUdpServer())
    }

    @Test
    fun `a QUIC flow to another host is forwarded once its server name is read`() {
        start(blocked = listOf("tracker.example"))
        val localPort = nextPort++
        val datagrams = QuicInitialFixtures.clientInitialDatagrams(QuicInitialFixtures.clientHello("h3.example.org", listOf("h3")), datagrams = 1, shuffle = false)
        val connection = datagrams.map { sendUdp(it, localPort) }.last()

        assertEquals(datagrams.size, receivedAtUdpServer())
        assertFalse(connection.blockedByRule)
        assertTrue(icmpErrors().isEmpty())
    }
}
