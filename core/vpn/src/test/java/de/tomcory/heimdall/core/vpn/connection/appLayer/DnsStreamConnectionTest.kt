package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import de.tomcory.heimdall.core.vpn.metadata.DnsCache
import io.mockk.every
import io.mockk.mockk
import io.mockk.verifyOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * Tests for docs/vpn-mitm-audit.md PKT-58: DNS over a stream (TCP to port 53, decrypted DNS over
 * TLS) frames each message with a two-byte length.
 */
class DnsStreamConnectionTest {

    private lateinit var dnsCache: DnsCache
    private lateinit var encryptionLayer: EncryptionLayerConnection
    private lateinit var connection: DnsStreamConnection

    @Before
    fun setup() {
        dnsCache = DnsCache()
        val componentManager: ComponentManager = mockk(relaxed = true)
        every { componentManager.dnsCache } returns dnsCache
        encryptionLayer = mockk(relaxed = true)
        // id=0 skips the init block's log line
        connection = DnsStreamConnection(0, encryptionLayer, componentManager)
    }

    /** A DNS response for [name] with one answer of [type] (1 = A, 28 = AAAA) carrying [address]. */
    private fun response(name: String, type: Int, address: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 1, 0, 0, 0, 0))
        name.split('.').forEach { label ->
            out.write(label.length)
            out.write(label.toByteArray())
        }
        out.write(0)
        out.write(byteArrayOf(0, type.toByte(), 0, 1))
        // answer: pointer to the question's name, type, class IN, TTL 300, address
        out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, type.toByte(), 0, 1, 0, 0, 0x01, 0x2C, 0, address.size.toByte()))
        out.write(address)
        return out.toByteArray()
    }

    private fun framed(message: ByteArray): ByteArray =
        byteArrayOf((message.size shr 8).toByte(), message.size.toByte()) + message

    private val aResponse = response("a.example", 1, byteArrayOf(93, 184.toByte(), 216.toByte(), 34))
    private val aaaaResponse = response("v6.example", 28, ByteArray(16) { if (it == 0) 0x26 else it.toByte() })

    @Test
    fun `a whole message fills the cache from an A answer`() {
        connection.unwrapInbound(framed(aResponse))
        assertEquals("a.example", dnsCache.get("93.184.216.34"))
    }

    @Test
    fun `an AAAA answer fills the cache`() {
        connection.unwrapInbound(framed(aaaaResponse))
        assertEquals("v6.example", dnsCache.get("2601:203:405:607:809:a0b:c0d:e0f"))
    }

    @Test
    fun `a message split inside its length prefix is reassembled`() {
        val bytes = framed(aResponse)
        connection.unwrapInbound(bytes.copyOfRange(0, 1))
        assertNull(dnsCache.get("93.184.216.34"))
        connection.unwrapInbound(bytes.copyOfRange(1, 10))
        assertNull(dnsCache.get("93.184.216.34"))
        connection.unwrapInbound(bytes.copyOfRange(10, bytes.size))
        assertEquals("a.example", dnsCache.get("93.184.216.34"))
    }

    @Test
    fun `two messages in one segment are both read`() {
        connection.unwrapInbound(framed(aResponse) + framed(aaaaResponse))
        assertEquals("a.example", dnsCache.get("93.184.216.34"))
        assertEquals("v6.example", dnsCache.get("2601:203:405:607:809:a0b:c0d:e0f"))
    }

    @Test
    fun `a message that cannot be read is skipped and the next one is still read`() {
        connection.unwrapInbound(framed(byteArrayOf(1, 2, 3)) + framed(aResponse))
        assertEquals("a.example", dnsCache.get("93.184.216.34"))
    }

    @Test
    fun `every byte is passed on unchanged and at once, in both directions`() {
        val bytes = framed(aResponse)
        val first = bytes.copyOfRange(0, 7)
        val second = bytes.copyOfRange(7, bytes.size)
        val query = framed(byteArrayOf(9, 9, 9))

        connection.unwrapOutbound(query)
        connection.unwrapInbound(first)
        connection.unwrapInbound(second)

        verifyOrder {
            encryptionLayer.wrapOutbound(query)
            encryptionLayer.wrapInbound(first)
            encryptionLayer.wrapInbound(second)
        }
    }

    @Test
    fun `a stream that is not framed DNS is no longer read`() {
        // a zero length: no DNS message is empty
        connection.unwrapInbound(byteArrayOf(0, 0) + framed(aResponse))
        connection.unwrapInbound(framed(aResponse))
        assertNull(dnsCache.get("93.184.216.34"))
    }
}
