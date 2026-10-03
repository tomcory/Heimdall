package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.UdpConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.QuicInitialFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import de.tomcory.heimdall.core.vpn.mitm.MitmScope
import de.tomcory.heimdall.core.vpn.quic.QuicPolicy
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.channels.DatagramChannel

/**
 * docs/vpn-mitm-audit.md PKT-52: with MitM on and the Block policy, an HTTP/3 flow whose TLS
 * fallback would be intercepted is blocked and answered with an ICMP error; every other flow
 * is forwarded unchanged.
 */
class QuicBlockPolicyTest {

    private lateinit var server: DatagramSocket
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var dbConnector: RecordingDatabaseConnector
    private lateinit var deviceWriter: RecordingDeviceWriter

    private val localAddr = InetAddress.getByName("10.0.0.98") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private var nextPort = 46000

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        server = DatagramSocket(0, remoteAddr).apply { soTimeout = 500 }
        deviceWriter = RecordingDeviceWriter()
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        server.close()
        ConnectionCache.closeAllAndClear()
    }

    private fun start(doMitm: Boolean = true, quicPolicy: QuicPolicy = QuicPolicy.BLOCK, mitmScope: MitmScope = MitmScope.ALL) {
        dbConnector = RecordingDatabaseConnector()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(), doMitm = doMitm, databaseConnector = dbConnector,
            mitmScope = mitmScope, quicPolicy = quicPolicy
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()
    }

    private fun flight(sni: String, alpn: List<String>, datagrams: Int = 1, ech: Boolean = false): List<ByteArray> {
        val clientHello = QuicInitialFixtures.clientHello(sni, alpn, extraLength = if (datagrams > 1) 1300 else 0, ech = ech)
        return QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = datagrams, shuffle = datagrams > 1)
    }

    private fun send(datagrams: List<ByteArray>, localPort: Int = nextPort++): TransportLayerConnection {
        var connection: TransportLayerConnection? = null
        for (datagram in datagrams) {
            val packet = PacketFixtures.buildUdpPacket(localAddr, localPort, remoteAddr, server.localPort, datagram)
            connection = TransportLayerConnection.getInstance(packet, componentManager, deviceWriter.handler)!!
            connection.unwrapOutbound(packet.payload)
        }
        return connection!!
    }

    private fun receivedAtServer(): List<ByteArray> {
        val received = mutableListOf<ByteArray>()
        while (true) {
            val buffer = ByteArray(2048)
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                server.receive(packet)
            } catch (e: SocketTimeoutException) {
                return received
            }
            received.add(buffer.copyOf(packet.length))
        }
    }

    private fun icmpErrors(): List<ByteArray> =
        deviceWriter.sentMessages.filter { it.what == DeviceWriteThread.WRITE_ICMP }.map { it.obj as ByteArray }

    private fun awaitUntil(message: String, timeoutMs: Long = 3000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(20)
        }
        throw AssertionError(message)
    }

    private fun assertForwarded(datagrams: List<ByteArray>) {
        val received = receivedAtServer()
        assertEquals("every datagram must be forwarded", datagrams.size, received.size)
        datagrams.indices.forEach { assertArrayEquals("datagram $it must arrive unchanged and in order", datagrams[it], received[it]) }
        assertTrue("nothing may be answered with an ICMP error", icmpErrors().isEmpty())
        Thread.sleep(200)
        assertFalse(dbConnector.connections.single().blocked)
    }

    @Test
    fun `an in-scope HTTP3 flow is blocked and answered with an ICMP error`() {
        start()
        val datagrams = flight("h3.example", listOf("h3"))
        val connection = send(datagrams)

        assertTrue("nothing may reach the remote host", receivedAtServer().isEmpty())
        val icmp = icmpErrors().single()
        assertEquals("ICMP", 1, icmp[9].toInt())
        assertEquals("port unreachable", 3, icmp[21].toInt())
        awaitUntil("the row must be marked blocked") { dbConnector.connections.single().blocked }
        assertEquals("h3.example", dbConnector.connections.single().sni)

        val channel = UdpConnection::class.java.getDeclaredField("selectableChannel").apply { isAccessible = true }.get(connection) as DatagramChannel
        assertFalse("the flow's socket must be released at once", channel.isOpen)
        assertTrue("the flow must stay cached for its retransmissions", ConnectionCache.allConnections().contains(connection))
    }

    @Test
    fun `retransmissions of a blocked flow are dropped without new rows, and ICMP errors are limited`() {
        start()
        val datagrams = flight("again.example", listOf("h3"))
        val localPort = nextPort++
        repeat(6) { send(datagrams, localPort) }

        assertTrue(receivedAtServer().isEmpty())
        assertEquals("no further connection rows", 1, dbConnector.connections.size)
        assertEquals("at most three ICMP errors per flow", 3, icmpErrors().size)
    }

    @Test
    fun `a ClientHello over two datagrams is blocked only once both are in`() {
        start()
        val datagrams = flight("split.example", listOf("h3"), datagrams = 2)
        send(datagrams)
        assertTrue(receivedAtServer().isEmpty())
        assertEquals("both held datagrams are answered", 2, icmpErrors().size)
    }

    @Test
    fun `a ClientHello over two datagrams is flushed in order when it is not blocked`() {
        start()
        val datagrams = flight("split-doq.example", listOf("doq"), datagrams = 2)
        send(datagrams)
        assertForwarded(datagrams)
    }

    @Test
    fun `a flow without an h3 offer is forwarded`() {
        start()
        val datagrams = flight("doq.example", listOf("doq"))
        send(datagrams)
        assertForwarded(datagrams)
    }

    @Test
    fun `an h3 draft token counts as HTTP3`() {
        start()
        send(flight("draft.example", listOf("h3-29")))
        assertTrue(receivedAtServer().isEmpty())
        assertEquals(1, icmpErrors().size)
    }

    @Test
    fun `a host outside the MitM scope is forwarded`() {
        start(mitmScope = MitmScope(hostMode = MitmScope.HostMode.BLACKLIST, hosts = listOf("excluded.example")))
        val datagrams = flight("excluded.example", listOf("h3"))
        send(datagrams)
        assertForwarded(datagrams)
    }

    @Test
    fun `a host with learned passthrough is forwarded`() {
        start()
        componentManager.tlsPassthroughCache.put(1000, "pinned.example")
        val datagrams = flight("pinned.example", listOf("h3"))
        send(datagrams)
        assertForwarded(datagrams)
    }

    @Test
    fun `with MitM off or the Passthrough policy nothing is blocked`() {
        start(doMitm = false)
        val first = flight("nomitm.example", listOf("h3"))
        send(first)
        assertForwarded(first)

        pump.stop()
        ConnectionCache.closeAllAndClear()
        start(quicPolicy = QuicPolicy.PASSTHROUGH)
        val second = flight("passthrough.example", listOf("h3"))
        send(second)
        assertForwarded(second)
    }

    @Test
    fun `a flow whose ClientHello cannot be read is forwarded`() {
        start()
        val datagram = flight("broken.example", listOf("h3")).single().copyOf()
        datagram[600] = (datagram[600].toInt() xor 0x01).toByte()
        send(listOf(datagram))
        assertForwarded(listOf(datagram))
    }

    @Test
    fun `with ECH the decision uses the SNI, as the TLS path does`() {
        start()
        // the DNS cache knows the address under another name, which ECH keeps as the hostname
        componentManager.dnsCache.put(remoteAddr.hostAddress!!, "dns-name.example")
        componentManager.tlsPassthroughCache.put(1000, "public-name.example")

        val datagrams = flight("public-name.example", listOf("h3"), ech = true)
        val connection = send(datagrams)

        // passthrough was learned for the SNI, so the TLS path would not intercept: forward
        assertForwarded(datagrams)
        assertEquals("the hostname stays the DNS name with ECH", "dns-name.example", connection.remoteHost)
    }
}
