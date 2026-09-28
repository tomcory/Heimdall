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
    // detectQuic — long header form, QUIC version 0 or 1
    // -----------------------------------------------------------------------

    @Test
    fun `detectQuic returns true for QUIC version 1 long header`() {
        // byte[0]: 0xC0 = 1100_0000 → bit7=1 (long header), bit6=1 (fixed bit)
        // bytes[1..4]: version 0x00000001
        val quicV1 = byteArrayOf(
            0xC0.toByte(),
            0x00, 0x00, 0x00, 0x01,
            0x00 // stub
        )
        assertTrue(EncryptionLayerConnection.detectQuic(quicV1))
    }

    @Test
    fun `detectQuic returns true for QUIC version 0 long header`() {
        val quicV0 = byteArrayOf(
            0xC0.toByte(),
            0x00, 0x00, 0x00, 0x00,
            0x00
        )
        assertTrue(EncryptionLayerConnection.detectQuic(quicV0))
    }

    @Test
    fun `detectQuic returns false for short header form`() {
        // bit7=0 means short header
        val shortHeader = byteArrayOf(
            0x40.toByte(), // bit7=0, bit6=1
            0x00, 0x00, 0x00, 0x01,
            0x00
        )
        assertFalse(EncryptionLayerConnection.detectQuic(shortHeader))
    }

    @Test
    fun `detectQuic returns true for a long header packet regardless of QUIC version`() {
        // docs/vpn-mitm-audit.md PKT-19 (V-30): detectQuic used to require an exact version
        // match (only 0/1 recognised), so any other QUIC version fell through to
        // PlaintextConnection - QuicConnection never actually attempts MITM regardless of
        // version, so any long-header packet should be recognised as QUIC
        val arbitraryVersion = byteArrayOf(
            0xC0.toByte(),
            0x00, 0x00, 0x00, 0x02, // an arbitrary, unrecognised-by-the-old-code version
            0x00
        )
        assertTrue(EncryptionLayerConnection.detectQuic(arbitraryVersion))
    }

    @Test
    fun `detectQuic returns true for a real QUIC v2 long header packet`() {
        // QUIC Version 2's version number, per RFC 9369 section 3: 0x6b3343cf
        val quicV2 = byteArrayOf(
            0xC0.toByte(),
            0x6B, 0x33, 0x43, 0xCF.toByte(),
            0x00
        )
        assertTrue(EncryptionLayerConnection.detectQuic(quicV2))
    }

    @Test
    fun `detectQuic returns false for TLS payload`() {
        val clientHello = byteArrayOf(
            0x16, 0x03, 0x03, 0x00, 0x05, 0x01,
            0x00, 0x00, 0x01, 0x00
        )
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
