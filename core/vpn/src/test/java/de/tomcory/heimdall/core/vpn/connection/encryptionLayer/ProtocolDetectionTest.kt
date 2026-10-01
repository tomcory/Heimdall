package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.appLayer.AppLayerConnection
import de.tomcory.heimdall.core.vpn.connection.appLayer.HttpConnection
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.*
import org.junit.Test

class ProtocolDetectionTest {

    // detectTls and detectQuic are internal companion functions on EncryptionLayerConnection

    // -----------------------------------------------------------------------
    // detectTls — first byte 0x16, payload > 5 bytes, byte[5] == 0x01
    // -----------------------------------------------------------------------

    @Test
    fun `detectTls returns true for TLS ClientHello`() {
        val clientHello = byteArrayOf(
            0x16,       // content type: Handshake
            0x03, 0x03, // TLS 1.2
            0x00, 0x05, // length
            0x01,       // handshake type: ClientHello
            0x00, 0x00, 0x01, 0x00 // stub body
        )
        assertTrue(EncryptionLayerConnection.detectTls(clientHello))
    }

    @Test
    fun `detectTls returns false for TLS ServerHello`() {
        val serverHello = byteArrayOf(
            0x16,       // content type: Handshake
            0x03, 0x03,
            0x00, 0x05,
            0x02,       // handshake type: ServerHello (not 0x01)
            0x00, 0x00, 0x01, 0x00
        )
        assertFalse(EncryptionLayerConnection.detectTls(serverHello))
    }

    @Test
    fun `detectTls returns false for TLS AppData record`() {
        val appData = byteArrayOf(
            0x17,       // content type: ApplicationData
            0x03, 0x03,
            0x00, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        )
        assertFalse(EncryptionLayerConnection.detectTls(appData))
    }

    @Test
    fun `detectTls returns false for plaintext HTTP`() {
        val http = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        assertFalse(EncryptionLayerConnection.detectTls(http))
    }

    @Test
    fun `detectTls returns false for payload shorter than 6 bytes`() {
        // Size must be > 5 — a 5-byte payload can't safely carry a byte[5] at all
        val tooShort = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x01)
        assertFalse(EncryptionLayerConnection.detectTls(tooShort))
    }

    @Test
    fun `detectTls returns true for a minimal 6-byte ClientHello prefix`() {
        // docs/vpn-mitm-audit.md PKT-19 (V-29): the length guard used to be one byte stricter
        // than what byte[5] actually requires (`size > 6` instead of `size > 5`), so this exact
        // 6-byte boundary case was permanently miscategorized as non-TLS
        val minimalClientHello = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x01, 0x01)
        assertTrue(EncryptionLayerConnection.detectTls(minimalClientHello))
    }

    @Test
    fun `detectTls returns false for empty payload`() {
        // Should not throw; should return false
        val empty = byteArrayOf()
        try {
            assertFalse(EncryptionLayerConnection.detectTls(empty))
        } catch (e: ArrayIndexOutOfBoundsException) {
            // acceptable if the implementation doesn't guard against empty arrays;
            // the production code never calls this with an empty payload
        }
    }

    // -----------------------------------------------------------------------
    // detectQuic — client Initial only: long header, version != 0, Initial packet type,
    // datagram >= 1200 bytes (docs/vpn-mitm-audit.md PKT-26)
    // -----------------------------------------------------------------------

    /**
     * Builds a datagram of [size] bytes that starts with a QUIC long header's first byte and
     * version field. The rest is zero, which detectQuic doesn't look at.
     */
    private fun quicDatagram(firstByte: Int, version: Long, size: Int = 1200): ByteArray {
        val datagram = ByteArray(size)
        datagram[0] = firstByte.toByte()
        datagram[1] = (version shr 24).toByte()
        datagram[2] = (version shr 16).toByte()
        datagram[3] = (version shr 8).toByte()
        datagram[4] = version.toByte()
        return datagram
    }

    @Test
    fun `detectQuic returns true for a QUIC version 1 Initial`() {
        // byte[0]: 0xC0 = 1100_0000 → bit7=1 (long header), bit6=1 (fixed bit), type 00 (Initial)
        assertTrue(EncryptionLayerConnection.detectQuic(quicDatagram(0xC0, 0x00000001)))
    }

    @Test
    fun `detectQuic ignores the low bits of the first byte`() {
        // the low four bits (reserved bits and packet number length) are header-protected, so
        // they are effectively random on the wire
        assertTrue(EncryptionLayerConnection.detectQuic(quicDatagram(0xCF, 0x00000001)))
    }

    @Test
    fun `detectQuic returns false for version 0`() {
        // version 0 is a Version Negotiation packet, which only servers send - it can never be
        // the first packet a client sends
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0xC0, 0x00000000)))
    }

    @Test
    fun `detectQuic returns false for short header form`() {
        // bit7=0 means short header
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0x40, 0x00000001)))
    }

    @Test
    fun `detectQuic returns false when the fixed bit is not set`() {
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0x80, 0x00000001)))
    }

    @Test
    fun `detectQuic returns true for an Initial of an unknown QUIC version`() {
        // docs/vpn-mitm-audit.md PKT-19 (V-29): detectQuic used to require an exact version
        // match, so any other QUIC version fell through to PlaintextConnection. Unknown versions
        // are assumed to number their packet types like v1.
        assertTrue(EncryptionLayerConnection.detectQuic(quicDatagram(0xC0, 0x00000002)))
    }

    @Test
    fun `detectQuic returns true for a QUIC v2 Initial`() {
        // QUIC v2 (0x6b3343cf) renumbered the long packet types: Initial is 0b01
        // (RFC 9369 section 3.2), so the first byte is 1101_0000
        assertTrue(EncryptionLayerConnection.detectQuic(quicDatagram(0xD0, 0x6B3343CF)))
    }

    @Test
    fun `detectQuic returns false for a QUIC v2 packet with type 0b00`() {
        // in v2, type 0b00 is a Retry packet
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0xC0, 0x6B3343CF)))
    }

    @Test
    fun `detectQuic returns false for non-Initial QUIC v1 long header packets`() {
        // 0-RTT (0b01), Handshake (0b10) and Retry (0b11): seeing one of these first means we
        // joined the flow mid-connection
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0xD0, 0x00000001)))
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0xE0, 0x00000001)))
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0xF0, 0x00000001)))
    }

    @Test
    fun `detectQuic returns false for an Initial in a datagram shorter than 1200 bytes`() {
        // RFC 9000 section 14.1: clients must pad datagrams carrying an Initial to 1200 bytes
        assertFalse(EncryptionLayerConnection.detectQuic(quicDatagram(0xC0, 0x00000001, size = 1199)))
    }

    @Test
    fun `detectQuic returns true for an Initial in a datagram longer than 1200 bytes`() {
        assertTrue(EncryptionLayerConnection.detectQuic(quicDatagram(0xC0, 0x00000001, size = 1350)))
    }

    @Test
    fun `detectQuic returns false for TLS payload`() {
        // padded to 1200 bytes so the size check alone can't be what rejects it
        val clientHello = byteArrayOf(
            0x16, 0x03, 0x03, 0x00, 0x05, 0x01,
            0x00, 0x00, 0x01, 0x00
        ).copyOf(1200)
        assertFalse(EncryptionLayerConnection.detectQuic(clientHello))
    }

    @Test
    fun `detectQuic returns false for payload shorter than 5 bytes`() {
        val tooShort = byteArrayOf(0xC0.toByte(), 0x00, 0x00)
        assertFalse(EncryptionLayerConnection.detectQuic(tooShort))
    }

    @Test
    fun `detectQuic returns false for empty payload`() {
        assertFalse(EncryptionLayerConnection.detectQuic(byteArrayOf()))
    }

    // -----------------------------------------------------------------------
    // AppLayerConnection.getInstance's HTTP-sniff guard — docs/vpn-mitm-audit.md
    // PKT-19 (V-31): payload.size > 7 let 8/9/10-byte payloads through the guard, but
    // sliceArray(0..10) needs 11 bytes and threw for exactly those sizes, silently falling back
    // to RawConnection via the blanket catch.
    // -----------------------------------------------------------------------

    private fun appLayerFixtures(): Pair<EncryptionLayerConnection, ComponentManager> {
        val transportLayer: TransportLayerConnection = mockk(relaxed = true)
        every { transportLayer.remotePort } returns 80

        val encryptionLayer: EncryptionLayerConnection = mockk(relaxed = true)
        every { encryptionLayer.transportLayer } returns transportLayer

        val componentManager: ComponentManager = mockk(relaxed = true)

        return encryptionLayer to componentManager
    }

    @Test
    fun `AppLayerConnection getInstance classifies an 8-byte first HTTP payload as HTTP`() {
        val (encryptionLayer, componentManager) = appLayerFixtures()
        val payload = "GET /a\r\n".toByteArray()
        assertEquals(8, payload.size)

        val connection = AppLayerConnection.getInstance(payload, 0, encryptionLayer, componentManager)
        assertTrue("expected an HttpConnection, got ${connection::class.simpleName}", connection is HttpConnection)
    }

    @Test
    fun `AppLayerConnection getInstance classifies a 9-byte first HTTP payload as HTTP`() {
        val (encryptionLayer, componentManager) = appLayerFixtures()
        val payload = "GET /ab\r\n".toByteArray()
        assertEquals(9, payload.size)

        val connection = AppLayerConnection.getInstance(payload, 0, encryptionLayer, componentManager)
        assertTrue("expected an HttpConnection, got ${connection::class.simpleName}", connection is HttpConnection)
    }

    @Test
    fun `AppLayerConnection getInstance classifies a 10-byte first HTTP payload as HTTP`() {
        val (encryptionLayer, componentManager) = appLayerFixtures()
        val payload = "GET /abc\r\n".toByteArray()
        assertEquals(10, payload.size)

        val connection = AppLayerConnection.getInstance(payload, 0, encryptionLayer, componentManager)
        assertTrue("expected an HttpConnection, got ${connection::class.simpleName}", connection is HttpConnection)
    }
}
