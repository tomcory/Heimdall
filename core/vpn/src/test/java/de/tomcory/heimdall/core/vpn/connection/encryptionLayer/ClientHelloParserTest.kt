package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext

/**
 * Tests for docs/vpn-mitm-audit.md PKT-29: [ClientHelloParser] reads SNI, ALPN, the offered TLS
 * versions and the presence of an ECH extension from a bare ClientHello handshake message.
 */
class ClientHelloParserTest {

    // -----------------------------------------------------------------------
    // builders
    // -----------------------------------------------------------------------

    private fun u16(value: Int) = byteArrayOf((value shr 8).toByte(), value.toByte())

    private fun extension(type: Int, body: ByteArray) = u16(type) + u16(body.size) + body

    private fun serverName(host: String): ByteArray {
        val entry = byteArrayOf(0x00) + u16(host.length) + host.toByteArray(Charsets.US_ASCII)
        return extension(0, u16(entry.size) + entry)
    }

    private fun alpn(vararg protocols: String): ByteArray {
        val list = protocols.fold(ByteArray(0)) { acc, p -> acc + byteArrayOf(p.length.toByte()) + p.toByteArray(Charsets.US_ASCII) }
        return extension(16, u16(list.size) + list)
    }

    private fun supportedVersions(vararg versions: Int): ByteArray {
        val list = versions.fold(ByteArray(0)) { acc, v -> acc + u16(v) }
        return extension(43, byteArrayOf(list.size.toByte()) + list)
    }

    private fun ech() = extension(0xfe0d, byteArrayOf(0x00, 0x00, 0x01, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x00))

    private fun unknownExtension() = extension(0x0a0a, byteArrayOf(0x00))

    /**
     * Builds a bare ClientHello handshake message.
     *
     * @param extensions The already-encoded extensions, or null to end the message after the
     * compression methods, as a ClientHello without any extensions does.
     */
    private fun clientHello(extensions: List<ByteArray>?, sessionId: ByteArray = ByteArray(32) { 0x55 }): ByteArray {
        val body = ByteArrayOutputStream()
        body.write(byteArrayOf(0x03, 0x03))                 // legacy_version
        body.write(ByteArray(32) { it.toByte() })           // random
        body.write(sessionId.size)
        body.write(sessionId)
        body.write(u16(4))                                  // cipher_suites length
        body.write(byteArrayOf(0x13, 0x01, 0x13, 0x02))
        body.write(byteArrayOf(0x01, 0x00))                 // legacy_compression_methods
        if (extensions != null) {
            val block = extensions.fold(ByteArray(0)) { acc, e -> acc + e }
            body.write(u16(block.size))
            body.write(block)
        }
        val bytes = body.toByteArray()
        return byteArrayOf(0x01, (bytes.size shr 16).toByte(), (bytes.size shr 8).toByte(), bytes.size.toByte()) + bytes
    }

    // -----------------------------------------------------------------------
    // well-formed messages
    // -----------------------------------------------------------------------

    @Test
    fun `parses a ClientHello that only carries an SNI`() {
        val info = ClientHelloParser.parse(clientHello(listOf(serverName("example.com"))))

        assertNotNull(info)
        assertEquals("example.com", info!!.sni)
        assertTrue(info.alpn.isEmpty())
        assertFalse(info.echOffered)
        assertTrue(info.supportedVersions.isEmpty())
        assertFalse(info.truncated)
    }

    @Test
    fun `parses ALPN entries in the client's order`() {
        val info = ClientHelloParser.parse(clientHello(listOf(serverName("example.com"), alpn("h2", "http/1.1"))))

        assertEquals(listOf("h2", "http/1.1"), info!!.alpn)
    }

    @Test
    fun `parses the offered TLS versions`() {
        val info = ClientHelloParser.parse(clientHello(listOf(supportedVersions(0x0304, 0x0303))))

        assertEquals(listOf(0x0304, 0x0303), info!!.supportedVersions)
    }

    @Test
    fun `detects an ECH extension`() {
        val info = ClientHelloParser.parse(clientHello(listOf(serverName("public-name.example"), ech())))

        assertTrue(info!!.echOffered)
        assertEquals("public-name.example", info.sni)
    }

    @Test
    fun `extensions are found regardless of their position and of unknown ones in between`() {
        val info = ClientHelloParser.parse(
            clientHello(listOf(unknownExtension(), alpn("h3"), unknownExtension(), supportedVersions(0x0304), serverName("quic.example"), ech()))
        )

        assertEquals("quic.example", info!!.sni)
        assertEquals(listOf("h3"), info.alpn)
        assertEquals(listOf(0x0304), info.supportedVersions)
        assertTrue(info.echOffered)
        assertFalse(info.truncated)
    }

    @Test
    fun `a ClientHello without an SNI yields a null SNI`() {
        val info = ClientHelloParser.parse(clientHello(listOf(alpn("h2"))))

        assertNotNull(info)
        assertNull(info!!.sni)
        assertEquals(listOf("h2"), info.alpn)
    }

    @Test
    fun `a ClientHello without an extensions block is accepted`() {
        val info = ClientHelloParser.parse(clientHello(extensions = null))

        assertNotNull(info)
        assertNull(info!!.sni)
        assertTrue(info.alpn.isEmpty())
        assertFalse(info.truncated)
    }

    @Test
    fun `an empty session id is accepted`() {
        // QUIC clients send an empty legacy_session_id
        val info = ClientHelloParser.parse(clientHello(listOf(serverName("example.com")), sessionId = ByteArray(0)))

        assertEquals("example.com", info!!.sni)
    }

    @Test
    fun `the message is parsed at the given offset`() {
        val message = clientHello(listOf(serverName("example.com")))
        val record = byteArrayOf(0x16, 0x03, 0x01) + u16(message.size) + message

        assertEquals("example.com", ClientHelloParser.parse(record, 5)!!.sni)
        // at offset 0 the record header is not a handshake message of type ClientHello
        assertNull(ClientHelloParser.parse(record))
    }

    @Test
    fun `parses a ClientHello produced by a real TLS stack`() {
        val engine = SSLContext.getDefault().createSSLEngine()
        engine.useClientMode = true
        engine.sslParameters = engine.sslParameters.apply {
            serverNames = listOf(SNIHostName("jsse.example.org"))
            applicationProtocols = arrayOf("h2", "http/1.1")
        }
        val out = ByteBuffer.allocate(engine.session.packetBufferSize)
        engine.beginHandshake()
        engine.wrap(ByteBuffer.allocate(0), out)
        out.flip()
        val record = ByteArray(out.remaining()).also { out.get(it) }

        val info = ClientHelloParser.parse(record, 5)

        assertNotNull(info)
        assertEquals("jsse.example.org", info!!.sni)
        assertEquals(listOf("h2", "http/1.1"), info.alpn)
        assertTrue("expected TLS 1.3 among ${info.supportedVersions}", info.supportedVersions.contains(0x0304))
        assertFalse(info.echOffered)
        assertFalse(info.truncated)
    }

    // -----------------------------------------------------------------------
    // malformed and truncated input
    // -----------------------------------------------------------------------

    @Test
    fun `input that is not a ClientHello yields null`() {
        val serverHello = clientHello(listOf(serverName("example.com"))).also { it[0] = 0x02 }

        assertNull(ClientHelloParser.parse(serverHello))
        assertNull(ClientHelloParser.parse(ByteArray(0)))
        assertNull(ClientHelloParser.parse(byteArrayOf(0x01, 0x00)))
        assertNull(ClientHelloParser.parse(clientHello(null), offset = 10_000))
        assertNull(ClientHelloParser.parse(clientHello(null), offset = -1))
    }

    @Test
    fun `a message cut off before its extensions yields null`() {
        val message = clientHello(listOf(serverName("example.com")))
        val extensionsStart = message.size - serverName("example.com").size - 2

        // every prefix that ends inside the fixed part, the session id, the cipher suites or the
        // compression methods
        for (length in 4 until extensionsStart) {
            assertNull("prefix of $length bytes", ClientHelloParser.parse(message.copyOf(length)))
        }
    }

    @Test
    fun `a message cut off at an extension boundary reports the complete extensions`() {
        val first = serverName("example.com")
        val second = alpn("h2", "http/1.1")
        val third = ech()
        val message = clientHello(listOf(first, second, third))
        val extensionsStart = message.size - first.size - second.size - third.size

        // nothing but the extensions length
        ClientHelloParser.parse(message.copyOf(extensionsStart))!!.let {
            assertNull(it.sni)
            assertTrue(it.truncated)
        }
        // SNI complete
        ClientHelloParser.parse(message.copyOf(extensionsStart + first.size))!!.let {
            assertEquals("example.com", it.sni)
            assertTrue(it.alpn.isEmpty())
            assertTrue(it.truncated)
        }
        // SNI and ALPN complete
        ClientHelloParser.parse(message.copyOf(extensionsStart + first.size + second.size))!!.let {
            assertEquals("example.com", it.sni)
            assertEquals(listOf("h2", "http/1.1"), it.alpn)
            assertFalse(it.echOffered)
            assertTrue(it.truncated)
        }
        // everything
        ClientHelloParser.parse(message)!!.let {
            assertTrue(it.echOffered)
            assertFalse(it.truncated)
        }
    }

    @Test
    fun `no prefix of a valid message makes the parser throw`() {
        val message = clientHello(listOf(unknownExtension(), serverName("example.com"), alpn("h2", "http/1.1"), supportedVersions(0x0304, 0x0303), ech()))

        for (length in 0..message.size) {
            ClientHelloParser.parse(message.copyOf(length))
        }
    }

    @Test
    fun `inconsistent inner lengths do not make the parser throw`() {
        val message = clientHello(listOf(serverName("example.com"), alpn("h2", "http/1.1"), supportedVersions(0x0304)))

        // set every single byte to 0xFF in turn, which corrupts each length field at some point
        for (index in message.indices) {
            val corrupted = message.copyOf().also { it[index] = 0xFF.toByte() }
            ClientHelloParser.parse(corrupted)
        }
    }

    @Test
    fun `a server name list that overruns its extension is ignored`() {
        // list length claims 0x4000 bytes, the extension only holds a few
        val broken = extension(0, byteArrayOf(0x40, 0x00, 0x00, 0x40, 0x00, 0x61, 0x62))
        val info = ClientHelloParser.parse(clientHello(listOf(broken, alpn("h2"))))

        assertNotNull(info)
        assertNull(info!!.sni)
        assertEquals(listOf("h2"), info.alpn)
    }
}
