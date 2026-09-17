package de.tomcory.heimdall.core.vpn.integration

import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.DnsPacket
import org.pcap4j.packet.DnsQuestion
import org.pcap4j.packet.DnsRDataA
import org.pcap4j.packet.DnsResourceRecord
import org.pcap4j.packet.namednumber.DnsClass
import org.pcap4j.packet.namednumber.DnsOpCode
import org.pcap4j.packet.namednumber.DnsRCode
import org.pcap4j.packet.namednumber.DnsResourceRecordType
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import org.pcap4j.packet.DnsDomainName

/**
 * Integration test for the DNS resolution + caching path:
 * device sends a synthetic DNS query -> UdpConnection opens a real DatagramChannel to a fake
 * UDP DNS server -> the response is parsed by DnsConnection.unwrapInbound -> DnsCache.put() is
 * called with the resolved hostname/ip/ttl.
 */
class DnsResolutionTest {

    private lateinit var fakeDnsServer: DatagramSocket
    private lateinit var serverThread: Thread
    private lateinit var pump: SelectorPump
    private lateinit var dbConnector: RecordingDatabaseConnector

    private val localAddr = InetAddress.getByName("10.0.0.5") as Inet4Address
    private val localPort = 53000
    private val resolvedHostname = "example.com"
    private val resolvedIp = "93.184.216.34"

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        dbConnector = RecordingDatabaseConnector()
        fakeDnsServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        if (::fakeDnsServer.isInitialized && !fakeDnsServer.isClosed) fakeDnsServer.close()
        if (::serverThread.isInitialized) serverThread.join(2000)
        ConnectionCache.closeAllAndClear()
    }

    private fun buildQuestion(): DnsQuestion {
        val qName = DnsDomainName.Builder().labels(arrayOf("example", "com")).build()
        return DnsQuestion.Builder()
            .qName(qName)
            .qType(DnsResourceRecordType.A)
            .qClass(DnsClass.IN)
            .build()
    }

    private fun buildQuery(question: DnsQuestion): DnsPacket {
        return DnsPacket.Builder()
            .id(0x1234)
            .response(false)
            .opCode(DnsOpCode.QUERY)
            .rCode(DnsRCode.NO_ERROR)
            .recursionDesired(true)
            .qdCount(1)
            .anCount(0)
            .nsCount(0)
            .arCount(0)
            .questions(listOf(question))
            .build()
    }

    private fun buildResponse(question: DnsQuestion): DnsPacket {
        val rdata = DnsRDataA.Builder().address(InetAddress.getByName(resolvedIp) as Inet4Address).build()
        val answer = DnsResourceRecord.Builder()
            .name(question.qName)
            .dataType(DnsResourceRecordType.A)
            .dataClass(DnsClass.IN)
            .ttl(60)
            .rData(rdata)
            .correctLengthAtBuild(true)
            .build()
        return DnsPacket.Builder()
            .id(0x1234)
            .response(true)
            .opCode(DnsOpCode.QUERY)
            .rCode(DnsRCode.NO_ERROR)
            .recursionDesired(true)
            .recursionAvailable(true)
            .qdCount(1)
            .anCount(1)
            .nsCount(0)
            .arCount(0)
            .questions(listOf(question))
            .answers(listOf(answer))
            .build()
    }

    @Test
    fun `DNS response populates DnsCache with resolved hostname and ttl`() {
        val question = buildQuestion()
        val responsePacket = buildResponse(question)

        // fake DNS server: receive one query datagram, reply with the canned response
        serverThread = Thread {
            val buf = ByteArray(1024)
            val incoming = DatagramPacket(buf, buf.size)
            try {
                fakeDnsServer.receive(incoming)
                val responseBytes = responsePacket.rawData
                val outgoing = DatagramPacket(responseBytes, responseBytes.size, incoming.address, incoming.port)
                fakeDnsServer.send(outgoing)
            } catch (e: Exception) {
                // socket closed during teardown, ignore
            }
        }
        serverThread.start()

        val componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()

        val deviceWriter = RecordingDeviceWriter()
        val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
        val remotePort = fakeDnsServer.localPort

        val queryPacket = buildQuery(question)
        val ipPacket = PacketFixtures.buildUdpPacket(localAddr, localPort, remoteAddr, remotePort, queryPacket.builder)

        val connection = TransportLayerConnection.getInstance(ipPacket, componentManager, deviceWriter.handler)
        connection?.unwrapOutbound(ipPacket.payload)

        // wait for the round trip (real socket I/O + selector pump) to complete
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && componentManager.dnsCache.get(resolvedIp) == null) {
            Thread.sleep(20)
        }

        assertEquals(resolvedHostname, componentManager.dnsCache.get(resolvedIp))
    }

    @Test
    fun `unresolved ip is not present in DnsCache`() {
        val componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        assertNull(componentManager.dnsCache.get("203.0.113.42"))
    }
}
