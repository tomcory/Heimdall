package de.tomcory.heimdall.core.vpn.components

import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.namednumber.IpNumber
import org.pcap4j.util.IpV4Helper
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Tests for docs/vpn-mitm-audit.md PKT-46 (V-54): a UDP datagram larger than the tunnel's MTU
 * reaches the VPN as IP fragments, which have to be put back together before the datagram can
 * be forwarded.
 */
class IpV4ReassemblerTest {

    private val localAddr = InetAddress.getByName("10.120.0.1") as Inet4Address
    private val remoteAddr = InetAddress.getByName("203.0.113.5") as Inet4Address

    private var clock = 1_000_000L

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
    }

    private fun payload(size: Int, seed: Int = 0) = ByteArray(size) { (it * 13 + seed).toByte() }

    /** The fragments the device's IP stack makes of a UDP datagram, re-parsed from their bytes as the VPN reads them. */
    private fun fragments(payload: ByteArray, identification: Int, localPort: Int = 40000): List<IpV4Packet> {
        val udp = PacketFixtures.buildUdpSegment(localAddr, remoteAddr, localPort, 9999, payload)
        val datagram = PacketFixtures.buildIpV4Packet(localAddr, remoteAddr, IpNumber.UDP, udp, identification)
        return IpV4Helper.fragment(datagram, 1500).map { IpV4Packet.newPacket(it.rawData, 0, it.rawData.size) }
    }

    private fun assertWhole(expectedPayload: ByteArray, datagram: IpV4Packet?) {
        assertNotNull("the datagram must be complete", datagram)
        assertFalse(IpV4Reassembler.isFragment(datagram!!))
        // as the rest of the pipeline needs it: a UDP packet with its header and the whole payload
        val udp = datagram.payload as UdpPacket
        assertEquals(9999, udp.header.dstPort.valueAsInt())
        assertArrayEquals(expectedPayload, udp.payload.rawData)
        assertEquals(20 + 8 + expectedPayload.size, datagram.header.totalLengthAsInt)
    }

    @Test
    fun `fragments in order are put back together`() {
        val reassembler = IpV4Reassembler()
        val data = payload(8000)
        val parts = fragments(data, identification = 7)
        assertEquals(6, parts.size)
        assertTrue(parts.all { IpV4Reassembler.isFragment(it) })

        parts.dropLast(1).forEach { assertNull("incomplete until the last fragment", reassembler.add(it)) }
        assertWhole(data, reassembler.add(parts.last()))
        assertEquals(0, reassembler.pendingCount)
    }

    @Test
    fun `fragments out of order and repeated are put back together`() {
        val reassembler = IpV4Reassembler()
        val data = payload(4000)
        val parts = fragments(data, identification = 8)
        assertEquals(3, parts.size)

        assertNull(reassembler.add(parts[2]))
        assertNull(reassembler.add(parts[2])) // a duplicate changes nothing
        assertNull(reassembler.add(parts[0]))
        assertWhole(data, reassembler.add(parts[1]))
    }

    @Test
    fun `datagrams whose fragments are interleaved are kept apart`() {
        val reassembler = IpV4Reassembler()
        val first = payload(4000, seed = 1)
        val second = payload(4000, seed = 2)
        val a = fragments(first, identification = 20, localPort = 40001)
        val b = fragments(second, identification = 21, localPort = 40002)

        assertNull(reassembler.add(a[0]))
        assertNull(reassembler.add(b[0]))
        assertNull(reassembler.add(a[1]))
        assertNull(reassembler.add(b[1]))
        assertEquals(2, reassembler.pendingCount)
        assertWhole(second, reassembler.add(b[2]))
        assertWhole(first, reassembler.add(a[2]))
    }

    @Test
    fun `an incomplete datagram is dropped after the timeout`() {
        val reassembler = IpV4Reassembler(timeoutMs = 5000, now = { clock })
        val parts = fragments(payload(4000), identification = 30)

        assertNull(reassembler.add(parts[0]))
        assertNull(reassembler.add(parts[1]))
        assertEquals(1, reassembler.pendingCount)

        // the last fragment arrives too late: the first two are gone, so it cannot complete anything
        clock += 5001
        assertNull(reassembler.add(parts[2]))
        assertEquals("only the late fragment may be waiting now", 1, reassembler.pendingCount)

        // and it goes the same way
        clock += 5001
        assertNull(reassembler.add(fragments(payload(4000), identification = 31)[0]))
        assertEquals(1, reassembler.pendingCount)
    }

    @Test
    fun `the number of incomplete datagrams is bounded`() {
        val reassembler = IpV4Reassembler(maxPending = 4)
        val firstParts = fragments(payload(4000), identification = 100)
        assertNull(reassembler.add(firstParts[0]))
        for (identification in 101..110) {
            assertNull(reassembler.add(fragments(payload(4000), identification)[0]))
        }
        assertEquals(4, reassembler.pendingCount)

        // the oldest was dropped to make room, so its remaining fragments complete nothing
        assertNull(reassembler.add(firstParts[1]))
        assertNull(reassembler.add(firstParts[2]))
    }

    @Test
    fun `a packet that is not fragmented is not taken for a fragment`() {
        val whole = PacketFixtures.buildUdpPacket(localAddr, 40000, remoteAddr, 9999, payload(1200))
        assertFalse(IpV4Reassembler.isFragment(IpV4Packet.newPacket(whole.rawData, 0, whole.rawData.size)))
    }
}
