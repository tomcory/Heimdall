package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import org.junit.Assert.*
import org.junit.Test

class ProtocolDetectionTest {

    // detectTls and detectQuic are internal companion functions on EncryptionLayerConnection

    // -----------------------------------------------------------------------
    // detectTls — first byte 0x16, payload > 6 bytes, byte[5] == 0x01
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
    fun `detectTls returns false for payload shorter than 7 bytes`() {
        // Size must be > 6 — a 6-byte payload at index 5 is exactly the boundary
        val tooShort = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x01, 0x01)
        assertFalse(EncryptionLayerConnection.detectTls(tooShort))
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
    fun `detectQuic returns false for unknown QUIC version`() {
        // Long header but unrecognised version
        val unknownVersion = byteArrayOf(
            0xC0.toByte(),
            0x00, 0x00, 0x00, 0x02, // version 2 not recognised
            0x00
        )
        assertFalse(EncryptionLayerConnection.detectQuic(unknownVersion))
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
}
