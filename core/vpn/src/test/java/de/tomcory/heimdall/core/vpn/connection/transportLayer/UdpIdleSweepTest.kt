package de.tomcory.heimdall.core.vpn.connection.transportLayer

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Regression tests for docs/vpn-mitm-audit.md PKT-13 (V-22): unlike TCP, UDP has no FIN/RST of
 * its own to signal "this flow is done", so without an idle sweep, every UDP "connection" (other
 * than the DNS special-case, which self-closes after its first reply) stays registered - holding
 * a DatagramChannel fd and its buffers - for the entire VPN session.
 */
class UdpIdleSweepTest {

    private lateinit var fakeServer: DatagramSocket

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        fakeServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
    }

    @After
    fun teardown() {
        if (::fakeServer.isInitialized && !fakeServer.isClosed) fakeServer.close()
        ConnectionCache.closeAllAndClear()
    }

    @Test
    fun `an idle UDP connection is closed and removed from the cache by sweepIdleConnections`() {
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.30") as Inet4Address
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

        val udpPacket = PacketFixtures.buildUdpPacket(localAddr, 51000, remoteAddr, fakeServer.localPort, byteArrayOf(1, 2, 3))
        val connection = TransportLayerConnection.getInstance(udpPacket, componentManager, deviceWriter.handler)
        assertNotNull("expected a UdpConnection to be created", connection)
        assertNotNull("expected the connection to be tracked in the cache", ConnectionCache.findConnection(udpPacket))

        // "now" far enough in the future that the connection (whose lastActivityAt is ~now, from
        // construction) looks idle under a short timeout
        val future = System.currentTimeMillis() + 60_000
        UdpConnection.sweepIdleConnections(idleTimeoutMs = 1_000, now = future)

        assertNull("expected the idle connection to have been removed from the cache", ConnectionCache.findConnection(udpPacket))
    }

    @Test
    fun `a recently-active UDP connection is not reaped`() {
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.31") as Inet4Address
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

        val udpPacket = PacketFixtures.buildUdpPacket(localAddr, 51001, remoteAddr, fakeServer.localPort, byteArrayOf(1, 2, 3))
        val connection = TransportLayerConnection.getInstance(udpPacket, componentManager, deviceWriter.handler)
        assertNotNull(connection)

        // "now" close to the connection's actual (just-now) lastActivityAt, well within the timeout
        UdpConnection.sweepIdleConnections(idleTimeoutMs = 60_000, now = System.currentTimeMillis())

        assertNotNull("expected the recently-active connection to still be cached", ConnectionCache.findConnection(udpPacket))

        connection?.closeHard()
    }

    @Test
    fun `a TCP connection is never touched by the UDP sweep`() {
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir())
        val deviceWriter = RecordingDeviceWriter()
        val localAddr = InetAddress.getByName("10.0.0.32") as Inet4Address
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address

        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, 51002, remoteAddr, 12345)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        assertNotNull(connection)

        // an extreme "everything is idle" sweep - would reap any UdpConnection, but must not
        // touch a TcpConnection regardless of how idle it looks
        UdpConnection.sweepIdleConnections(idleTimeoutMs = 0, now = System.currentTimeMillis() + 1_000_000)

        assertNotNull("TCP connections must not be affected by the UDP idle sweep", ConnectionCache.findConnection(synPacket))

        connection?.closeHard()
    }
}
