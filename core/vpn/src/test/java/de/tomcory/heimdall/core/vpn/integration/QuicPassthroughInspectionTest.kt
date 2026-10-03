package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.DatabaseConnector
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.QuicConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.QuicInitialFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import de.tomcory.heimdall.core.vpn.quic.QuicInitialInspector
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * docs/vpn-mitm-audit.md PKT-50: a QUIC flow is passed through unchanged while its ClientHello
 * is read, and what it revealed ends up on the connection's row.
 */
class QuicPassthroughInspectionTest {

    private lateinit var server: DatagramSocket
    private lateinit var pump: SelectorPump
    private lateinit var componentManager: ComponentManager
    private lateinit var dbConnector: RecordingDatabaseConnector
    private lateinit var deviceWriter: RecordingDeviceWriter

    private val localAddr = InetAddress.getByName("10.0.0.99") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        server = DatagramSocket(0, remoteAddr).apply { soTimeout = 3000 }
        dbConnector = RecordingDatabaseConnector()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir(), databaseConnector = dbConnector)
        pump = SelectorPump(componentManager.selector)
        pump.start()
        deviceWriter = RecordingDeviceWriter()
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        server.close()
        ConnectionCache.closeAllAndClear()
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 5000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(20)
        }
        throw AssertionError(message)
    }

    /** Sends [datagrams] from the device on one flow and returns the flow's transport connection. */
    private fun sendFromDevice(localPort: Int, datagrams: List<ByteArray>): TransportLayerConnection {
        var connection: TransportLayerConnection? = null
        for (datagram in datagrams) {
            val packet = PacketFixtures.buildUdpPacket(localAddr, localPort, remoteAddr, server.localPort, datagram)
            connection = TransportLayerConnection.getInstance(packet, componentManager, deviceWriter.handler)!!
            connection.unwrapOutbound(packet.payload)
        }
        return connection!!
    }

    private fun receiveAtServer(count: Int): List<ByteArray> = (0 until count).map {
        val buffer = ByteArray(2048)
        val packet = DatagramPacket(buffer, buffer.size)
        server.receive(packet)
        buffer.copyOf(packet.length)
    }

    private fun encryptionLayer(connection: TransportLayerConnection): EncryptionLayerConnection? {
        val field = TransportLayerConnection::class.java.getDeclaredField("encryptionLayer")
        field.isAccessible = true
        return field.get(connection) as EncryptionLayerConnection?
    }

    @Test
    fun `datagrams pass unchanged and the row gets QUIC, SNI, ALPN and the hostname`() {
        val clientHello = QuicInitialFixtures.clientHello("quic.example.org", listOf("h3", "h3-29"), extraLength = 1300)
        val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = 2, shuffle = true)

        val connection = sendFromDevice(45000, flight)

        assertTrue(encryptionLayer(connection) is QuicConnection)
        val received = receiveAtServer(2)
        assertArrayEquals("the first datagram must arrive unchanged", flight[0], received[0])
        assertArrayEquals("the second datagram must arrive unchanged", flight[1], received[1])

        awaitUntil("the ClientHello must be recorded") { dbConnector.connections.firstOrNull()?.sni != null }
        val row = dbConnector.connections.single()
        assertEquals(SecurityProtocol.QUIC, row.securityProtocol)
        assertEquals("quic.example.org", row.sni)
        assertEquals("h3,h3-29", row.alpn)
        awaitUntil("the hostname must be refined from the SNI") { row.remoteHost == "quic.example.org" }
        assertEquals("quic.example.org", connection.remoteHost)
    }

    @Test
    fun `the ClientHello's details are not overwritten by the earlier QUIC label`() {
        // the label written when the flow is created reaches the database late
        val slowFirstWrite = object : DatabaseConnector by dbConnector {
            private val first = AtomicBoolean(true)
            override suspend fun updateConnectionSecurity(id: Long, securityProtocol: SecurityProtocol, sni: String?, alpn: String?, echOffered: Boolean) {
                if (first.getAndSet(false)) delay(300)
                dbConnector.updateConnectionSecurity(id, securityProtocol, sni, alpn, echOffered)
            }
        }
        every { componentManager.databaseConnector } returns slowFirstWrite

        val clientHello = QuicInitialFixtures.clientHello("ordered.example", listOf("h3"))
        sendFromDevice(45003, QuicInitialFixtures.clientInitialDatagrams(clientHello))
        receiveAtServer(1)

        Thread.sleep(800)
        val row = dbConnector.connections.single()
        assertEquals("ordered.example", row.sni)
        assertEquals("h3", row.alpn)
    }

    @Test
    fun `a flow whose ClientHello cannot be read is still passed through`() {
        // a datagram that is classified as QUIC but does not decrypt
        val datagram = QuicInitialFixtures.clientInitialDatagrams(QuicInitialFixtures.clientHello("x.example", listOf("h3"))).single()
        datagram[600] = (datagram[600].toInt() xor 0x01).toByte()

        sendFromDevice(45001, listOf(datagram, datagram))

        val received = receiveAtServer(2)
        assertArrayEquals(datagram, received[0])
        assertArrayEquals(datagram, received[1])
        Thread.sleep(300)
        assertEquals(SecurityProtocol.QUIC, dbConnector.connections.single().securityProtocol)
        assertNull(dbConnector.connections.single().sni)
    }

    @Test
    fun `an inspector that throws costs nothing but the inspection`() {
        val clientHello = QuicInitialFixtures.clientHello("throws.example", listOf("h3"), extraLength = 1300)
        val flight = QuicInitialFixtures.clientInitialDatagrams(clientHello, datagrams = 2)

        val connection = sendFromDevice(45002, flight.take(1))
        val quic = encryptionLayer(connection) as QuicConnection
        val failing = mockk<QuicInitialInspector>()
        every { failing.offer(any()) } throws IllegalStateException("broken on purpose")
        QuicConnection::class.java.getDeclaredField("inspector").apply { isAccessible = true }.set(quic, failing)

        sendFromDevice(45002, flight.drop(1) + flight.take(1))

        val received = receiveAtServer(3)
        assertArrayEquals(flight[0], received[0])
        assertArrayEquals(flight[1], received[1])
        assertArrayEquals(flight[0], received[2])
        assertEquals(TransportLayerConnection.TransportLayerState.CONNECTED, connection.state)
        assertTrue(ConnectionCache.allConnections().contains(connection))
        assertNull(dbConnector.connections.single().sni)
    }
}
