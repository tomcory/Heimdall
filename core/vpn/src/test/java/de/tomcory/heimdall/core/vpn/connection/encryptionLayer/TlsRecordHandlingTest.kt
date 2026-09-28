package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.metadata.TlsPassthroughCache
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLSession

class TlsRecordHandlingTest {

    private lateinit var transportLayer: TransportLayerConnection
    private lateinit var componentManager: ComponentManager
    private lateinit var tlsConnection: TlsConnection

    @Before
    fun setup() {
        componentManager = mockk(relaxed = true)
        every { componentManager.doMitm } returns false
        every { componentManager.tlsPassthroughCache } returns TlsPassthroughCache()

        transportLayer = mockk(relaxed = true)
        every { transportLayer.remoteHost } returns null
        every { transportLayer.remotePort } returns 443
        every { transportLayer.appId } returns null

        // id=0 skips all Timber.d init-block logs that access property chains
        tlsConnection = TlsConnection(0, transportLayer, componentManager)
    }

    // -----------------------------------------------------------------------
    // parseRecordType
    // -----------------------------------------------------------------------

    @Test
    fun `parseRecordType identifies ChangeCipherSpec`() {
        val payload = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
        assertEquals(TlsConnection.RecordType.CHANGE_CIPHER_SPEC, tlsConnection.parseRecordType(payload))
    }

    @Test
    fun `parseRecordType identifies Alert`() {
        val payload = byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28.toByte())
        assertEquals(TlsConnection.RecordType.ALERT, tlsConnection.parseRecordType(payload))
    }

    @Test
    fun `parseRecordType identifies ClientHello`() {
        val payload = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00)
        assertEquals(TlsConnection.RecordType.HANDSHAKE_CLIENT_HELLO, tlsConnection.parseRecordType(payload))
    }

    @Test
    fun `parseRecordType identifies ServerHello`() {
        val payload = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00)
        assertEquals(TlsConnection.RecordType.HANDSHAKE_SERVER_HELLO, tlsConnection.parseRecordType(payload))
    }

    @Test
    fun `parseRecordType identifies ApplicationData`() {
        val payload = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03)
        assertEquals(TlsConnection.RecordType.APP_DATA, tlsConnection.parseRecordType(payload))
    }

    @Test
    fun `parseRecordType returns HANDSHAKE_INVALID when payload has exactly 5 bytes`() {
        // Only 5 bytes → no room for the handshake type at index 5
        val payload = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x01)
        assertEquals(TlsConnection.RecordType.HANDSHAKE_INVALID, tlsConnection.parseRecordType(payload))
    }

    @Test
    fun `parseRecordType returns INDETERMINATE for unknown record type`() {
        val payload = byteArrayOf(0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03)
        assertEquals(TlsConnection.RecordType.INDETERMINATE, tlsConnection.parseRecordType(payload))
    }

    @Test
    fun `parseRecordType returns HANDSHAKE_INDETERMINATE for unknown handshake type`() {
        val payload = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x05, 0xFF.toByte(), 0x00, 0x00, 0x00, 0x00)
        assertEquals(TlsConnection.RecordType.HANDSHAKE_INDETERMINATE, tlsConnection.parseRecordType(payload))
    }

    // -----------------------------------------------------------------------
    // findSni
    // -----------------------------------------------------------------------

    @Test
    fun `findSni extracts SNI from ClientHello with server_name extension`() {
        // Full TLS record: 5-byte header + ClientHello body containing SNI "example.com"
        // Indices:
        //   0    = 0x16 (Handshake)
        //   1-2  = 0x03, 0x03 (TLS 1.2)
        //   3-4  = record length (0x00, 0x43 = 67)
        //   5    = 0x01 (ClientHello)
        //   6-8  = handshake body length (0x00, 0x00, 0x3F = 63)
        //   9-10 = client version (0x03, 0x03)
        //   11-42= random (32 bytes)
        //   43   = session ID length (0x00)
        //   44-45= cipher suites length (0x00, 0x02)
        //   46-47= cipher suite (0x00, 0x2F)
        //   48   = compression methods length (0x01)
        //   49   = compression method (0x00)
        //   50-51= extensions length (0x00, 0x14 = 20)
        //   52-53= extension type server_name (0x00, 0x00)
        //   54-55= extension data length (0x00, 0x10 = 16)
        //   56-57= server name list length (0x00, 0x0E = 14)
        //   58   = name type host_name (0x00)
        //   59-60= hostname length (0x00, 0x0B = 11)
        //   61-71= "example.com" (11 bytes)
        val clientHello = byteArrayOf(
            0x16, 0x03, 0x03, 0x00, 0x43,          // TLS record header
            0x01, 0x00, 0x00, 0x3F,                 // Handshake header
            0x03, 0x03,                              // Client version
            // Random (32 bytes: indices 11-42)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x00,                                    // Session ID length (index 43)
            0x00, 0x02,                              // Cipher suites length
            0x00, 0x2F,                              // TLS_RSA_WITH_AES_128_CBC_SHA
            0x01,                                    // Compression methods length
            0x00,                                    // Null compression
            0x00, 0x14,                              // Extensions length = 20
            0x00, 0x00,                              // Extension type: server_name
            0x00, 0x10,                              // Extension data length = 16
            0x00, 0x0E,                              // Server name list length = 14
            0x00,                                    // Name type: host_name
            0x00, 0x0B,                              // Hostname length = 11
            0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D  // "example.com"
        )
        assertEquals("example.com", tlsConnection.findSni(clientHello))
    }

    @Test
    fun `findSni returns null when no server_name extension present`() {
        // Same structure but with a different extension type (0xFF, 0x01 = renegotiation_info)
        val clientHello = byteArrayOf(
            0x16, 0x03, 0x03, 0x00, 0x43,
            0x01, 0x00, 0x00, 0x3F,
            0x03, 0x03,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x00,                                    // Session ID length (index 43)
            0x00, 0x02,                              // Cipher suites length
            0x00, 0x2F,
            0x01,
            0x00,
            0x00, 0x07,                              // Extensions length = 7
            0xFF.toByte(), 0x01,                     // Extension type: renegotiation_info (not SNI)
            0x00, 0x03,                              // Extension data length = 3
            0x02, 0xAA.toByte(), 0xBB.toByte()       // stub extension data
        )
        assertNull(tlsConnection.findSni(clientHello))
    }

    // -----------------------------------------------------------------------
    // prepareRecords (exercised via unwrapOutbound)
    // Records flow: unwrapOutbound → prepareRecords → processRecord →
    //   handleOutboundRecord (doMitm=false) → passOutboundToAppLayer →
    //   RawConnection.unwrapOutbound → tlsConnection.wrapOutbound →
    //   transportLayer.wrapOutbound
    // -----------------------------------------------------------------------

    private fun appData(vararg data: Byte): ByteArray {
        val header = byteArrayOf(0x17, 0x03, 0x03,
            (data.size shr 8).toByte(), (data.size and 0xFF).toByte())
        return header + data
    }

    @Test
    fun `prepareRecords passes a single complete record to wrapOutbound`() {
        val record = appData(0x01, 0x02, 0x03, 0x04, 0x05)
        val slot = slot<ByteArray>()

        tlsConnection.unwrapOutbound(record)

        verify(exactly = 1) { transportLayer.wrapOutbound(capture(slot)) }
        assertArrayEquals(record, slot.captured)
    }

    @Test
    fun `prepareRecords does not forward until fragmented record is complete`() {
        // 10-byte record: 5-byte header + 5-byte body
        // Split: part1 has header + 2 bytes → 3 still needed
        val part1 = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x05, 0xAA.toByte(), 0xBB.toByte())
        val part2 = byteArrayOf(0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte())

        tlsConnection.unwrapOutbound(part1)
        verify(exactly = 0) { transportLayer.wrapOutbound(any()) }

        tlsConnection.unwrapOutbound(part2)
        val slot = slot<ByteArray>()
        verify(exactly = 1) { transportLayer.wrapOutbound(capture(slot)) }
        assertArrayEquals(part1 + part2, slot.captured)
    }

    @Test
    fun `prepareRecords processes both records when two are packed into one payload`() {
        val record1 = appData(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        val record2 = appData(0x01, 0x02)
        val packed = record1 + record2

        val captured = mutableListOf<ByteArray>()
        every { transportLayer.wrapOutbound(any()) } answers {
            captured.add(firstArg<ByteArray>().copyOf())
        }

        tlsConnection.unwrapOutbound(packed)

        assertEquals(2, captured.size)
        assertArrayEquals(record1, captured[0])
        assertArrayEquals(record2, captured[1])
    }

    @Test
    fun `prepareRecords stashes tiny snippet and combines it with the next payload`() {
        // Send only 3 bytes (less than the 5-byte TLS header minimum)
        val snippet = byteArrayOf(0x17, 0x03, 0x03)
        // Send the rest: remaining header + body
        val rest = byteArrayOf(0x00, 0x02, 0xAA.toByte(), 0xBB.toByte())
        val fullRecord = snippet + rest

        tlsConnection.unwrapOutbound(snippet)
        verify(exactly = 0) { transportLayer.wrapOutbound(any()) }

        val slot = slot<ByteArray>()
        tlsConnection.unwrapOutbound(rest)
        verify(exactly = 1) { transportLayer.wrapOutbound(capture(slot)) }
        assertArrayEquals(fullRecord, slot.captured)
    }

    @Test
    fun `prepareRecords drops payload with invalid record type byte`() {
        // Type 0x13 is not in 0x14..0x17
        val invalid = byteArrayOf(0x13, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02)
        tlsConnection.unwrapOutbound(invalid)
        verify(exactly = 0) { transportLayer.wrapOutbound(any()) }
    }

    @Test
    fun `prepareRecords correctly handles continuation that itself triggers another record`() {
        // Three-way split: part1 is header + 1 data byte, part2 has 2 more bytes + a second complete record
        val body1 = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte()) // 3 bytes
        val record1 = appData(*body1)     // 8 bytes total

        val record2 = appData(0x01, 0x02) // 7 bytes total

        val part1 = record1.sliceArray(0..5)  // header(5) + 1 byte of body
        val part2 = record1.sliceArray(6..7) + record2  // remaining 2 bytes of body + full record2

        val captured = mutableListOf<ByteArray>()
        every { transportLayer.wrapOutbound(any()) } answers {
            captured.add(firstArg<ByteArray>().copyOf())
        }

        tlsConnection.unwrapOutbound(part1)
        assertEquals(0, captured.size)

        tlsConnection.unwrapOutbound(part2)
        assertEquals(2, captured.size)
        assertArrayEquals(record1, captured[0])
        assertArrayEquals(record2, captured[1])
    }

    // -----------------------------------------------------------------------
    // PKT-04 (docs/vpn-mitm-audit.md V-11/V-13): BUFFER_UNDERFLOW retry cap and
    // handshake-setup coroutine exception guards. handleWrap/handleUnwrap and the
    // initiate*Handshake methods are private, so they're driven via reflection.
    // -----------------------------------------------------------------------

    private fun setPrivateField(target: Any, fieldName: String, value: Any?) {
        val field = TlsConnection::class.java.getDeclaredField(fieldName)
        field.isAccessible = true
        field.set(target, value)
    }

    @Test
    fun `handleUnwrap terminates via closeConnection after repeated BUFFER_UNDERFLOW instead of recursing forever`() {
        var unwrapCallCount = 0
        val fakeEngine: SSLEngine = mockk(relaxed = true)
        every { fakeEngine.unwrap(any<ByteBuffer>(), any<ByteBuffer>()) } answers {
            unwrapCallCount++
            SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0)
        }
        // isOutbound=false routes through serverSSLEngine in handleUnwrap
        setPrivateField(tlsConnection, "serverSSLEngine", fakeEngine)

        val handleUnwrap = TlsConnection::class.java.getDeclaredMethod(
            "handleUnwrap", ByteArray::class.java, Boolean::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType
        )
        handleUnwrap.isAccessible = true
        handleUnwrap.invoke(tlsConnection, byteArrayOf(1, 2, 3, 4, 5), false, 2, 0)

        // maxBufferUnderflowRetries (5) retries -> 6 total unwrap() calls, not unbounded recursion
        assertEquals(6, unwrapCallCount)
        verify { transportLayer.closeHard() }
    }

    @Test
    fun `initiateServerHandshake closes the connection instead of crashing if setupServerSSLEngine throws`() {
        every { componentManager.mitmManager.createServerSSLEngine(any(), any()) } throws RuntimeException("boom in createServerSSLEngine")

        val initiateServerHandshake = TlsConnection::class.java.getDeclaredMethod("initiateServerHandshake", ByteArray::class.java)
        initiateServerHandshake.isAccessible = true
        initiateServerHandshake.invoke(tlsConnection, byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x01, 0x01))

        // setupServerSSLEngine() runs on a launched coroutine, so wait for the async close
        verify(timeout = 5000) { transportLayer.closeHard() }
    }

    @Test
    fun `initiateClientHandshake closes the connection instead of crashing if setupClientSSLEngine throws`() {
        val fakeServerEngine: SSLEngine = mockk(relaxed = true)
        val fakeSession: SSLSession = mockk(relaxed = true)
        every { fakeServerEngine.session } returns fakeSession
        setPrivateField(tlsConnection, "serverSSLEngine", fakeServerEngine)

        every { componentManager.mitmManager.createClientSSLEngineFor(any()) } throws RuntimeException("boom in createClientSSLEngineFor")

        val initiateClientHandshake = TlsConnection::class.java.getDeclaredMethod("initiateClientHandshake")
        initiateClientHandshake.isAccessible = true
        initiateClientHandshake.invoke(tlsConnection)

        verify(timeout = 5000) { transportLayer.closeHard() }
    }

    // -----------------------------------------------------------------------
    // PKT-05 (docs/vpn-mitm-audit.md V-12): outbound records arriving before the
    // client-facing handshake is ready (e.g. a ClientHello split across multiple TLS
    // records) are buffered and replayed, not treated as a protocol violation.
    // `state` and `bufferedOutboundRecords` are private, and ConnectionState is a
    // private nested enum, so they're read via reflection, comparing by enum name.
    // -----------------------------------------------------------------------

    private fun readStateName(target: TlsConnection): String {
        val field = TlsConnection::class.java.getDeclaredField("state")
        field.isAccessible = true
        return (field.get(target) as Enum<*>).name
    }

    private fun readBufferedOutboundRecordCount(target: TlsConnection): Int {
        val field = TlsConnection::class.java.getDeclaredField("bufferedOutboundRecords")
        field.isAccessible = true
        return (field.get(target) as List<*>).size
    }

    private fun handshakeRecord(handshakeType: Byte, bodySize: Int = 32): ByteArray {
        val body = byteArrayOf(handshakeType) + ByteArray(bodySize) { it.toByte() }
        val header = byteArrayOf(0x16, 0x03, 0x03, (body.size shr 8).toByte(), (body.size and 0xFF).toByte())
        return header + body
    }

    @Test
    fun `a ClientHello split across two TLS records is buffered and reaches SERVER_HANDSHAKE instead of being closed`() {
        val mitmComponentManager: ComponentManager = mockk(relaxed = true)
        every { mitmComponentManager.doMitm } returns true
        every { mitmComponentManager.tlsPassthroughCache } returns TlsPassthroughCache()

        val mitmTransportLayer: TransportLayerConnection = mockk(relaxed = true)
        every { mitmTransportLayer.remoteHost } returns null
        every { mitmTransportLayer.remotePort } returns 443
        every { mitmTransportLayer.appId } returns null

        val mitmConnection = TlsConnection(0, mitmTransportLayer, mitmComponentManager)

        // record #1: a complete, well-framed TLS record containing a ClientHello (handshake type 0x01)
        val record1 = handshakeRecord(0x01)
        // record #2: a second, independently-framed TLS record - as if it were a continuation of
        // the same (oversized) ClientHello handshake message, or TLS 1.3 early data sent right
        // after it. Its handshake-type byte (0xAB) isn't a recognized fresh message type.
        val record2 = handshakeRecord(0xAB.toByte())

        mitmConnection.unwrapOutbound(record1)

        // initiateServerHandshake() runs on a launched coroutine
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline && readStateName(mitmConnection) == "NEW") {
            Thread.sleep(20)
        }
        assertEquals("SERVER_HANDSHAKE", readStateName(mitmConnection))

        mitmConnection.unwrapOutbound(record2)

        // the second record must be buffered for later replay, not close the connection
        assertEquals("SERVER_HANDSHAKE", readStateName(mitmConnection))
        assertEquals(1, readBufferedOutboundRecordCount(mitmConnection))
        verify(exactly = 0) { mitmTransportLayer.closeHard() }
    }
}
