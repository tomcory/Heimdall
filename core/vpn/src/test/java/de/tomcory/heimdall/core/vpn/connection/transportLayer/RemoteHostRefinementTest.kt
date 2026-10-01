package de.tomcory.heimdall.core.vpn.connection.transportLayer

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordedConnection
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import io.mockk.every
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Tests for docs/vpn-mitm-audit.md PKT-28 (V-39): a connection's hostname and tracker label come
 * from a reverse lookup in the DNS cache when the connection is created, and
 * [TransportLayerConnection.refineRemoteHost] lets the encryption layer correct both once the
 * client's ClientHello has named the server.
 */
class RemoteHostRefinementTest {

    private lateinit var fakeServer: DatagramSocket
    private lateinit var dbConnector: RecordingDatabaseConnector
    private lateinit var componentManager: ComponentManager

    private val localAddr = InetAddress.getByName("10.0.0.40") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private var nextLocalPort = 52000

    private val trackerHost = "tracker.example"

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        fakeServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        dbConnector = RecordingDatabaseConnector()
        componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        every { componentManager.labelConnection(trackerHost) } returns true
    }

    @After
    fun teardown() {
        ConnectionCache.closeAllAndClear()
        if (::fakeServer.isInitialized && !fakeServer.isClosed) fakeServer.close()
    }

    /**
     * Creates a UDP connection to [fakeServer], optionally with a name for its address in the
     * DNS cache, as if the app had resolved it through the VPN beforehand.
     */
    private fun newConnection(dnsName: String?): TransportLayerConnection {
        dnsName?.let { componentManager.dnsCache.put(remoteAddr.hostAddress!!, it) }
        val packet = PacketFixtures.buildUdpPacket(localAddr, nextLocalPort++, remoteAddr, fakeServer.localPort, byteArrayOf(1, 2, 3))
        return TransportLayerConnection.getInstance(packet, componentManager, RecordingDeviceWriter().handler)!!
    }

    /** The host update is written asynchronously; waits until the recorded row satisfies [condition]. */
    private fun awaitRow(condition: (RecordedConnection) -> Boolean): RecordedConnection {
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && !condition(dbConnector.connections.last())) {
            Thread.sleep(10)
        }
        return dbConnector.connections.last()
    }

    @Test
    fun `a DNS-derived hostname is replaced by a differing SNI`() {
        val connection = newConnection(dnsName = "cdn.example")
        assertEquals("cdn.example", connection.remoteHost)

        connection.refineRemoteHost("api.example", echOffered = false)

        assertEquals("api.example", connection.remoteHost)
        val row = awaitRow { it.remoteHost == "api.example" }
        assertEquals("api.example", row.remoteHost)
        assertFalse(row.isTracker)
    }

    @Test
    fun `a missing hostname is filled from the SNI`() {
        val connection = newConnection(dnsName = null)
        assertNull(connection.remoteHost)
        assertNull(dbConnector.connections.last().remoteHost)

        connection.refineRemoteHost("api.example", echOffered = false)

        assertEquals("api.example", connection.remoteHost)
        assertEquals("api.example", awaitRow { it.remoteHost != null }.remoteHost)
    }

    @Test
    fun `the tracker label is re-evaluated for the refined hostname`() {
        val connection = newConnection(dnsName = "cdn.example")
        assertFalse(dbConnector.connections.last().isTracker)

        connection.refineRemoteHost(trackerHost, echOffered = false)

        val row = awaitRow { it.isTracker }
        assertEquals(trackerHost, row.remoteHost)
        assertTrue(row.isTracker)
    }

    @Test
    fun `the tracker label is cleared when the DNS-derived name was a tracker and the SNI is not`() {
        val connection = newConnection(dnsName = trackerHost)
        assertTrue(dbConnector.connections.last().isTracker)

        connection.refineRemoteHost("api.example", echOffered = false)

        val row = awaitRow { !it.isTracker }
        assertEquals("api.example", row.remoteHost)
        assertFalse(row.isTracker)
    }

    @Test
    fun `the SNI is normalised before it is compared and stored`() {
        val connection = newConnection(dnsName = "api.example")

        connection.refineRemoteHost("API.Example.", echOffered = false)

        assertEquals("api.example", connection.remoteHost)
        // identical after normalisation, so nothing is written
        Thread.sleep(200)
        assertEquals("api.example", dbConnector.connections.last().remoteHost)
    }

    @Test
    fun `an existing hostname survives when ECH is offered`() {
        // with real ECH the outer SNI is only the provider's public name
        val connection = newConnection(dnsName = "secret.example")

        connection.refineRemoteHost("public-name.example", echOffered = true)

        assertEquals("secret.example", connection.remoteHost)
        Thread.sleep(200)
        assertEquals("secret.example", dbConnector.connections.last().remoteHost)
    }

    @Test
    fun `a missing hostname is filled from the SNI even when ECH is offered`() {
        val connection = newConnection(dnsName = null)

        connection.refineRemoteHost("public-name.example", echOffered = true)

        assertEquals("public-name.example", connection.remoteHost)
        assertEquals("public-name.example", awaitRow { it.remoteHost != null }.remoteHost)
    }

    @Test
    fun `an empty SNI changes nothing`() {
        val connection = newConnection(dnsName = "cdn.example")

        connection.refineRemoteHost("", echOffered = false)

        assertEquals("cdn.example", connection.remoteHost)
    }
}
