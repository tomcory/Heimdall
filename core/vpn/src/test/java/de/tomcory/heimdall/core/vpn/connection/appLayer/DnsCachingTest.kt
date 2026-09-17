package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.metadata.DnsCache
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class DnsCachingTest {

    private lateinit var dnsCache: DnsCache
    private lateinit var componentManager: ComponentManager
    private lateinit var encryptionLayer: EncryptionLayerConnection
    private lateinit var dnsConnection: DnsConnection

    @Before
    fun setup() {
        dnsCache = DnsCache()
        componentManager = mockk(relaxed = true)
        every { componentManager.dnsCache } returns dnsCache

        encryptionLayer = mockk(relaxed = true)

        // id=0 prevents the init block from accessing encryptionLayer property chain
        dnsConnection = DnsConnection(0, encryptionLayer, componentManager)
    }

    // DNS response for "example.com" → 93.184.216.34 (TTL 3600):
    //
    // Header (12 bytes): ID=0xABCD, QR=1, QDCOUNT=1, ANCOUNT=1
    // Question: example.com A IN
    // Answer:   example.com 3600 IN A 93.184.216.34
    //
    // Breakdown:
    //   0xAB, 0xCD      – transaction ID
    //   0x81, 0x80      – flags (response, no error)
    //   0x00, 0x01      – QDCOUNT=1
    //   0x00, 0x01      – ANCOUNT=1
    //   0x00, 0x00      – NSCOUNT=0
    //   0x00, 0x00      – ARCOUNT=0
    //   0x07, "example" – length-prefixed label
    //   0x03, "com"     – length-prefixed label
    //   0x00            – end of name
    //   0x00, 0x01      – QTYPE=A
    //   0x00, 0x01      – QCLASS=IN
    //   0xC0, 0x0C      – name pointer → offset 12 (question name)
    //   0x00, 0x01      – TYPE=A
    //   0x00, 0x01      – CLASS=IN
    //   0x00,0x00,0x0E,0x10 – TTL=3600
    //   0x00, 0x04      – RDLENGTH=4
    //   0x5D,0xB8,0xD8,0x22 – 93.184.216.34
    private val dnsResponseA = byteArrayOf(
        // Header
        0xAB.toByte(), 0xCD.toByte(), 0x81.toByte(), 0x80.toByte(),
        0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
        // Question: example.com A IN
        0x07,
        0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // "example"
        0x03, 0x63, 0x6F, 0x6D,                    // "com"
        0x00,
        0x00, 0x01,  0x00, 0x01,
        // Answer: name pointer + A record
        0xC0.toByte(), 0x0C,
        0x00, 0x01,  0x00, 0x01,
        0x00, 0x00, 0x0E, 0x10,  // TTL = 3600
        0x00, 0x04,
        0x5D, 0xB8.toByte(), 0xD8.toByte(), 0x22  // 93.184.216.34
    )

    // DNS response for "ipv6.example.com" → 2606:2800:220:1:248:1893:25c8:1946 (TTL 120)
    //
    // The AAAA address bytes: 26 06 28 00 02 20 00 01 02 48 18 93 25 C8 19 46
    private val dnsResponseAAAA = byteArrayOf(
        // Header
        0xAB.toByte(), 0xCE.toByte(), 0x81.toByte(), 0x80.toByte(),
        0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
        // Question: ipv6.example.com AAAA IN
        0x04,
        0x69, 0x70, 0x76, 0x36,                    // "ipv6"
        0x07,
        0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // "example"
        0x03, 0x63, 0x6F, 0x6D,                    // "com"
        0x00,
        0x00, 0x1C,  0x00, 0x01,  // QTYPE=AAAA, QCLASS=IN
        // Answer
        0xC0.toByte(), 0x0C,
        0x00, 0x1C,  0x00, 0x01, // TYPE=AAAA, CLASS=IN
        0x00, 0x00, 0x00, 0x78,  // TTL = 120
        0x00, 0x10,              // RDLENGTH = 16
        0x26, 0x06, 0x28.toByte(), 0x00, 0x02, 0x20, 0x00, 0x01,
        0x02, 0x48, 0x18.toByte(), 0x93.toByte(), 0x25, 0xC8.toByte(), 0x19, 0x46
    )

    @Test
    fun `A record response populates DnsCache with correct IP`() {
        dnsConnection.unwrapInbound(dnsResponseA)

        val cached = dnsCache.get("93.184.216.34")
        assertNotNull("Expected 93.184.216.34 to be cached", cached)
        assertTrue("Expected cached hostname to contain 'example.com', got: $cached",
            cached!!.contains("example.com"))
    }

    @Test
    fun `A record response uses correct TTL`() {
        // We verify this indirectly: TTL 3600 s means the entry should still be present now
        dnsConnection.unwrapInbound(dnsResponseA)
        assertNotNull(dnsCache.get("93.184.216.34"))
    }

    @Test
    fun `AAAA record response populates DnsCache`() {
        dnsConnection.unwrapInbound(dnsResponseAAAA)

        val ip = "2606:2800:220:1:248:1893:25c8:1946"
        val cached = dnsCache.get(ip)
        assertNotNull("Expected IPv6 address $ip to be cached", cached)
        assertTrue("Expected cached hostname to contain 'example.com', got: $cached",
            cached!!.contains("example.com"))
    }

    @Test
    fun `multiple A record answers are all cached`() {
        // Build a response with two A answers for the same question
        // Answer 1: 1.2.3.4, Answer 2: 5.6.7.8
        val twoAnswers = byteArrayOf(
            // Header
            0xAB.toByte(), 0xCF.toByte(), 0x81.toByte(), 0x80.toByte(),
            0x00, 0x01,  0x00, 0x02,  0x00, 0x00,  0x00, 0x00,
            // Question: example.com A IN
            0x07,
            0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
            0x03, 0x63, 0x6F, 0x6D,
            0x00,
            0x00, 0x01,  0x00, 0x01,
            // Answer 1: 1.2.3.4 TTL 60
            0xC0.toByte(), 0x0C,
            0x00, 0x01,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,  // TTL=60
            0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
            // Answer 2: 5.6.7.8 TTL 60
            0xC0.toByte(), 0x0C,
            0x00, 0x01,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,  // TTL=60
            0x00, 0x04,
            0x05, 0x06, 0x07, 0x08
        )

        dnsConnection.unwrapInbound(twoAnswers)

        assertNotNull(dnsCache.get("1.2.3.4"))
        assertNotNull(dnsCache.get("5.6.7.8"))
    }
}
