package de.tomcory.heimdall.core.vpn.connection.inetLayer

import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress

/** docs/vpn-mitm-audit.md PKT-52: the ICMP port unreachable error that answers a blocked QUIC datagram. */
class IcmpUnreachableBuilderTest {

    private val local = InetAddress.getByName("10.120.0.1") as Inet4Address
    private val remote = InetAddress.getByName("142.250.74.110") as Inet4Address
    private val payload = ByteArray(1200) { (it * 7).toByte() }

    private fun u8(data: ByteArray, i: Int) = data[i].toInt() and 0xFF
    private fun u16(data: ByteArray, i: Int) = (u8(data, i) shl 8) or u8(data, i + 1)

    @Test
    fun `the error goes from the remote host to the device and carries type 3 code 3`() {
        val packet = IcmpUnreachableBuilder.portUnreachable(local, 40000, remote, 443, payload)

        assertEquals(20 + 8 + 20 + 8, packet.size)
        assertEquals(0x45, u8(packet, 0))
        assertEquals(packet.size, u16(packet, 2))
        assertEquals("ICMP", 1, u8(packet, 9))
        assertArrayEquals("from the remote host", remote.address, packet.copyOfRange(12, 16))
        assertArrayEquals("to the device", local.address, packet.copyOfRange(16, 20))
        assertEquals("destination unreachable", 3, u8(packet, 20))
        assertEquals("port unreachable", 3, u8(packet, 21))
    }

    @Test
    fun `the quoted datagram is the one the app sent`() {
        val packet = IcmpUnreachableBuilder.portUnreachable(local, 40000, remote, 443, payload)
        val quoted = packet.copyOfRange(28, packet.size)

        // what the device actually sent, built independently with pcap4j
        val original = PacketFixtures.buildUdpPacket(local, 40000, remote, 443, payload).rawData
        assertEquals("UDP", 17, u8(quoted, 9))
        assertArrayEquals("source and destination of the datagram", original.copyOfRange(12, 20), quoted.copyOfRange(12, 20))
        assertEquals("total length of the datagram", 20 + 8 + payload.size, u16(quoted, 2))
        assertArrayEquals("the UDP header as sent, checksum included", original.copyOfRange(20, 28), quoted.copyOfRange(20, 28))
    }

    @Test
    fun `all checksums are valid`() {
        val packet = IcmpUnreachableBuilder.portUnreachable(local, 40000, remote, 443, payload)
        assertEquals("outer IP header", 0, IcmpUnreachableBuilder.checksum(packet, 0, 20))
        assertEquals("ICMP message", 0, IcmpUnreachableBuilder.checksum(packet, 20, packet.size - 20))
        assertEquals("quoted IP header", 0, IcmpUnreachableBuilder.checksum(packet, 28, 20))
    }

    @Test
    fun `an odd payload length gives the same UDP checksum as pcap4j`() {
        val odd = ByteArray(1201) { (it * 3).toByte() }
        val packet = IcmpUnreachableBuilder.portUnreachable(local, 51234, remote, 8443, odd)
        val original = PacketFixtures.buildUdpPacket(local, 51234, remote, 8443, odd).rawData
        assertArrayEquals(original.copyOfRange(20, 28), packet.copyOfRange(48, 56))
    }
}
