package de.tomcory.heimdall.core.vpn.cache

import de.tomcory.heimdall.core.vpn.connection.inetLayer.IpPacketBuilder
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.namednumber.IpNumber
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Regression tests for docs/vpn-mitm-audit.md PKT-15 (V-24): the old key was a hand-rolled
 * `remoteAddress.hashCode() xor (protocol shl 16) xor (localPort shl 8) xor remotePort` Int
 * whose localPort/remotePort bit ranges overlapped - e.g. (localPort=1, remotePort=0) and
 * (localPort=0, remotePort=256) both packed to `(1 shl 8) xor 0 == 256 == 0 xor 256`, so adding
 * the second connection silently overwrote the first's cache slot, orphaning it.
 */
class ConnectionCacheTest {

    private val remoteAddr: Inet4Address = InetAddress.getByName("93.184.216.34") as Inet4Address
    private val localAddr: Inet4Address = InetAddress.getByName("10.0.0.5") as Inet4Address

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
    }

    private fun fakeConnection(localPort: Int, remotePort: Int): TransportLayerConnection {
        val ipPacketBuilder: IpPacketBuilder = mockk(relaxed = true)
        every { ipPacketBuilder.remoteAddress } returns remoteAddr
        every { ipPacketBuilder.transportProtocol } returns IpNumber.UDP

        val connection: TransportLayerConnection = mockk(relaxed = true)
        every { connection.ipPacketBuilder } returns ipPacketBuilder
        every { connection.localPort } returns localPort
        every { connection.remotePort } returns remotePort
        return connection
    }

    @Test
    fun `previously colliding port tuples no longer overwrite each other`() {
        val connA = fakeConnection(localPort = 1, remotePort = 0)
        val connB = fakeConnection(localPort = 0, remotePort = 256)

        ConnectionCache.addConnection(connA)
        ConnectionCache.addConnection(connB)

        val packetA = PacketFixtures.buildUdpPacket(localAddr, 1, remoteAddr, 0, byteArrayOf(1))
        val packetB = PacketFixtures.buildUdpPacket(localAddr, 0, remoteAddr, 256, byteArrayOf(1))

        assertSame("connA should still be findable under its own key", connA, ConnectionCache.findConnection(packetA))
        assertSame("connB should still be findable under its own key", connB, ConnectionCache.findConnection(packetB))
        assertNotSame(connA, connB)
    }

    @Test
    fun `adding the second of a previously colliding pair does not evict the first`() {
        val connA = fakeConnection(localPort = 1, remotePort = 0)
        ConnectionCache.addConnection(connA)

        val connB = fakeConnection(localPort = 0, remotePort = 256)
        ConnectionCache.addConnection(connB)

        val packetA = PacketFixtures.buildUdpPacket(localAddr, 1, remoteAddr, 0, byteArrayOf(1))
        assertSame("connA must still be present after connB is added", connA, ConnectionCache.findConnection(packetA))
    }
}
