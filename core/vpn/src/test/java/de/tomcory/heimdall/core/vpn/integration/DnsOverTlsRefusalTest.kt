package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.components.DeviceWriteThread
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TcpConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Tests for docs/records/vpn-mitm-audit.md PKT-58: in Private DNS's opportunistic mode, connections to the
 * VPN's DNS server on port 853 are refused, so that the resolver falls back to plain DNS.
 */
class DnsOverTlsRefusalTest {

    private val localAddr = InetAddress.getByName("10.0.0.98") as Inet4Address
    private val dnsServer = InetAddress.getByName("127.0.0.53") as Inet4Address
    private val otherServer = InetAddress.getByName("127.0.0.54") as Inet4Address

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
    }

    @After
    fun teardown() {
        ConnectionCache.closeAllAndClear()
    }

    private fun open(refuseTo: InetAddress?, remote: Inet4Address, port: Int, deviceWriter: RecordingDeviceWriter): TransportLayerConnection? {
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(keyStoreDir = createTempDir(), refuseDnsOverTlsTo = refuseTo)
        val syn = PacketFixtures.buildTcpSynPacket(localAddr, 41900, remote, port, seq = 1000)
        return TransportLayerConnection.getInstance(syn, componentManager, deviceWriter.handler)
    }

    @Test
    fun `a SYN to the DNS server on port 853 is refused with a reset that acknowledges it`() {
        val deviceWriter = RecordingDeviceWriter()
        assertNull("no connection may be opened", open(dnsServer, dnsServer, 853, deviceWriter))

        val message = deviceWriter.sentMessages.single()
        assertEquals(DeviceWriteThread.WRITE_STRAY, message.what)
        val rst = (message.obj as IpPacket).payload as TcpPacket
        assertTrue(rst.header.rst)
        assertTrue("a reset refusing a SYN must carry ACK, or the device ignores it", rst.header.ack)
        assertEquals(1001, rst.header.acknowledgmentNumber)
        assertEquals(0, rst.header.sequenceNumber)
        assertEquals(41900, rst.header.dstPort.valueAsInt())
    }

    @Test
    fun `nothing is refused without the setting`() {
        val connection = open(null, dnsServer, 853, RecordingDeviceWriter())
        assertTrue(connection is TcpConnection)
    }

    @Test
    fun `other servers and other ports are not refused`() {
        assertTrue(open(dnsServer, otherServer, 853, RecordingDeviceWriter()) is TcpConnection)
        ConnectionCache.closeAllAndClear()
        assertTrue(open(dnsServer, dnsServer, 443, RecordingDeviceWriter()) is TcpConnection)
    }
}
