package de.tomcory.heimdall.core.vpn.connection.inetLayer

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.namednumber.IpNumber
import org.pcap4j.packet.namednumber.IpVersion
import java.net.Inet4Address
import java.net.InetAddress

class IpV4PacketBuilderTest {

    private val localAddr = InetAddress.getByName("10.0.0.1") as Inet4Address
    private val remoteAddr = InetAddress.getByName("93.184.216.34") as Inet4Address

    private lateinit var initialPacket: IpV4Packet
    private lateinit var builder: IpV4PacketBuilder

    @Before
    fun setup() {
        // Build a minimal IPv4 packet from raw bytes to avoid Pcap4j factory initialization issues.
        // Raw IPv4 header (20 bytes): version=4, IHL=5, TTL=128, protocol=TCP(6), src=10.0.0.1, dst=93.184.216.34
        // With no payload so we don't need TcpPacket.Builder.
        val rawIpv4 = byteArrayOf(
            0x45,               // version=4, IHL=5
            0x00,               // DSCP/ECN
            0x00, 0x14,         // total length = 20 (header only)
            0x00, 0x00,         // identification
            0x00, 0x00,         // flags/fragment offset
            0x80.toByte(),      // TTL = 128
            0x06,               // protocol = TCP
            0x00, 0x00,         // header checksum (computed below or left as 0)
            10, 0, 0, 1,        // src = 10.0.0.1
            93.toByte(), 184.toByte(), 216.toByte(), 34  // dst = 93.184.216.34
        )
        initialPacket = IpV4Packet.newPacket(rawIpv4, 0, rawIpv4.size)
        builder = IpV4PacketBuilder(initialPacket)
    }

    @Test
    fun `builder extracts localAddress from packet src`() {
        assertEquals(localAddr, builder.localAddress)
    }

    @Test
    fun `builder extracts remoteAddress from packet dst`() {
        assertEquals(remoteAddr, builder.remoteAddress)
    }

    @Test
    fun `buildPacket swaps src and dst addresses`() {
        val packet = builder.buildPacket(null) as IpV4Packet

        // src and dst must be swapped (response goes remote→local)
        assertEquals(remoteAddr, packet.header.srcAddr)
        assertEquals(localAddr, packet.header.dstAddr)
    }

    @Test
    fun `buildPacket sets TTL to 64`() {
        val packet = builder.buildPacket(null) as IpV4Packet
        assertEquals(64, packet.header.ttlAsInt)
    }

    @Test
    fun `buildPacket increments identification on each call`() {
        val id1 = (builder.buildPacket(null) as IpV4Packet).header.identificationAsInt
        val id2 = (builder.buildPacket(null) as IpV4Packet).header.identificationAsInt
        val id3 = (builder.buildPacket(null) as IpV4Packet).header.identificationAsInt

        assertEquals(id1 + 1, id2)
        assertEquals(id2 + 1, id3)
    }

    @Test
    fun `buildPacket preserves IP version 4`() {
        val packet = builder.buildPacket(null) as IpV4Packet
        assertEquals(IpVersion.IPV4, packet.header.version)
    }

    @Test
    fun `buildPacket preserves transport protocol`() {
        val packet = builder.buildPacket(null) as IpV4Packet
        assertEquals(IpNumber.TCP, packet.header.protocol)
    }

    @Test
    fun `buildStray swaps src and dst addresses`() {
        val stray = builder.buildPacket(null) as IpV4Packet
        val response = IpV4PacketBuilder.buildStray(stray, null)

        assertEquals(stray.header.dstAddr, response.header.srcAddr)
        assertEquals(stray.header.srcAddr, response.header.dstAddr)
    }

    @Test
    fun `buildStray increments identification by 1`() {
        val stray = builder.buildPacket(null) as IpV4Packet
        val response = IpV4PacketBuilder.buildStray(stray, null)

        assertEquals(stray.header.identificationAsInt + 1, response.header.identificationAsInt)
    }

    @Test
    fun `buildStray sets TTL to 64`() {
        val stray = builder.buildPacket(null) as IpV4Packet
        val response = IpV4PacketBuilder.buildStray(stray, null)

        assertEquals(64, response.header.ttlAsInt)
    }
}
