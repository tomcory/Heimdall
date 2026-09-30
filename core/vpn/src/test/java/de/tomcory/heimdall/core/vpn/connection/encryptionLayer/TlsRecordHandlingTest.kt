package de.tomcory.heimdall.core.vpn.connection.encryptionLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.metadata.TlsPassthroughCache
import de.tomcory.heimdall.core.vpn.mitm.MitmScope
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
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
        every { componentManager.mitmScope } returns MitmScope.ALL
        every { componentManager.learnPassthrough } returns true

        transportLayer = mockk(relaxed = true)
        every { transportLayer.remoteHost } returns null
        every { transportLayer.remotePort } returns 443
        every { transportLayer.appId } returns null

        // id=0 skips all Timber.d init-block logs that access property chains. Dispatchers.Unconfined
        // makes connectionScope.launch { ... } run its body eagerly on the calling thread (none of
        // these bodies ever suspend), so unwrapOutbound/unwrapInbound stay synchronous for these tests.
        tlsConnection = TlsConnection(0, transportLayer, componentManager, Dispatchers.Unconfined)
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
    fun `processRecord stops once the transport connection is already closed, instead of retrying every remaining attached record`() {
        // doMitm=false (this test class's default) means handleOutboundRecord's passthrough
        // branch never touches TlsConnection's own `state` - without a guard on the underlying
        // transport connection, every attached record after the one that closed it would
        // independently repeat the exact same doomed write and log its own redundant error.
        val record1 = appData(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        val record2 = appData(0x01, 0x02)
        val packed = record1 + record2

        var wrapOutboundCalls = 0
        // simulates transportLayer.wrapOutbound() failing on the first record and closing the
        // connection (as TcpConnection.wrapOutbound's catch block does on a real write failure)
        every { transportLayer.state } answers {
            if (wrapOutboundCalls == 0) TransportLayerConnection.TransportLayerState.CONNECTED
            else TransportLayerConnection.TransportLayerState.CLOSED
        }
        every { transportLayer.wrapOutbound(any()) } answers {
            wrapOutboundCalls++
        }

        tlsConnection.unwrapOutbound(packed)

        verify(exactly = 1) { transportLayer.wrapOutbound(any()) }
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
        // explicit, or the relaxed mock's MitmScope would veto MitM (PKT-24)
        every { mitmComponentManager.mitmScope } returns MitmScope.ALL
        every { mitmComponentManager.learnPassthrough } returns true

        // without this, createServerSSLEngine()'s fully-relaxed SSLEngine mock's wrap() call
        // returns a synthesized SSLEngineResult whose Status defaults to the first-declared enum
        // constant (BUFFER_UNDERFLOW) - handleWrap's underflow-retry-then-close path then closes
        // the connection deterministically a few synchronous calls later, which used to go
        // unnoticed because unwrapOutbound ran synchronously and assertions raced ahead of it.
        // Stub a believable "sent our part, now waiting for the peer's next message" result so
        // the handshake actually parks in SERVER_HANDSHAKE, matching what this test verifies.
        val fakeServerEngine: SSLEngine = mockk(relaxed = true)
        every { fakeServerEngine.wrap(any<ByteBuffer>(), any<ByteBuffer>()) } returns
            SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0)
        every { mitmComponentManager.mitmManager.createServerSSLEngine(any(), any()) } returns fakeServerEngine

        val mitmTransportLayer: TransportLayerConnection = mockk(relaxed = true)
        every { mitmTransportLayer.remoteHost } returns null
        every { mitmTransportLayer.remotePort } returns 443
        every { mitmTransportLayer.appId } returns null

        // Dispatchers.Unconfined: none of the dispatched bodies suspend, so this runs the whole
        // handshake-initiation chain eagerly/synchronously, same as every other test in this file
        val mitmConnection = TlsConnection(0, mitmTransportLayer, mitmComponentManager, Dispatchers.Unconfined)

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

    // -----------------------------------------------------------------------
    // V-26 (docs/vpn-mitm-audit.md): TlsConnection's state/buffers/reassembly caches used to
    // have zero synchronization despite being mutated both by whichever thread calls
    // unwrapOutbound/unwrapInbound and by untracked handshake coroutines. Fixed by confining all
    // mutation to a per-connection single-threaded dispatcher (connectionScope).
    // -----------------------------------------------------------------------

    @Test
    fun `state and bufferedOutboundRecords survive a concurrent burst of records during a handshake`() {
        // doMitm=true, unlike the passthrough test below - handleOutboundRecord/handleInboundRecord
        // both return before ever touching `state` when doMitm is false, so this is the only way
        // to actually exercise V-26's core hazard: `state` and `bufferedOutboundRecords`, mutated
        // both by the handshake coroutine (initiateServerHandshake, itself dispatched onto
        // connectionScope) and by whichever thread calls unwrapOutbound.
        val realComponentManager: ComponentManager = mockk(relaxed = true)
        every { realComponentManager.doMitm } returns true
        every { realComponentManager.tlsPassthroughCache } returns TlsPassthroughCache()
        // explicit, or the relaxed mock's MitmScope would veto MitM (PKT-24)
        every { realComponentManager.mitmScope } returns MitmScope.ALL
        every { realComponentManager.learnPassthrough } returns true

        // a believable "sent our part, now waiting" result, same as the split-ClientHello test
        // above - without this the handshake self-closes a few calls later regardless of thread
        // safety (an unrelated, pre-existing mock-fidelity gap, not a V-26 concern)
        val fakeServerEngine: SSLEngine = mockk(relaxed = true)
        every { fakeServerEngine.wrap(any<ByteBuffer>(), any<ByteBuffer>()) } returns
            SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0)
        every { realComponentManager.mitmManager.createServerSSLEngine(any(), any()) } returns fakeServerEngine

        val realTransportLayer: TransportLayerConnection = mockk(relaxed = true)
        every { realTransportLayer.remoteHost } returns null
        every { realTransportLayer.remotePort } returns 443
        every { realTransportLayer.appId } returns null

        val connection = TlsConnection(0, realTransportLayer, realComponentManager)

        // record #1 triggers initiateServerHandshake() -> SERVER_HANDSHAKE, itself dispatched
        // onto connectionScope (a coroutine running on some Dispatchers.IO worker thread)
        connection.unwrapOutbound(handshakeRecord(0x01))

        // meanwhile, a burst of records arrives on another thread and must all get buffered by
        // bufferOutboundRecord() - concurrently with the handshake coroutine mutating `state` and
        // (via replayBufferedOutboundRecords(), reachable once the handshake progresses further)
        // this same bufferedOutboundRecords list. Kept under maxBufferedOutboundRecords (16) so
        // the cap itself doesn't trigger a close.
        val extraRecordCount = 10
        val extraRecords = (0 until extraRecordCount).map { i -> handshakeRecord(0xAB.toByte(), bodySize = 8 + i) }
        val burstThread = Thread {
            extraRecords.forEach { connection.unwrapOutbound(it) }
        }
        burstThread.start()
        burstThread.join(15000)

        // everything above only enqueues work onto connectionScope; wait for it to drain
        val deadline = System.currentTimeMillis() + 15000
        while (System.currentTimeMillis() < deadline && readBufferedOutboundRecordCount(connection) < extraRecordCount) {
            Thread.sleep(20)
        }

        assertEquals("SERVER_HANDSHAKE", readStateName(connection))
        assertEquals(
            "every concurrently-submitted record must be buffered exactly once, none lost or duplicated",
            extraRecordCount,
            readBufferedOutboundRecordCount(connection)
        )
        verify(exactly = 0) { realTransportLayer.closeHard() }
    }

    @Test
    fun `concurrent outbound and inbound traffic on one connection is reassembled without corruption`() {
        // uses the REAL default dispatcher (no override) - this specifically tests that genuine
        // cross-thread concurrent dispatch is safe, not the synchronous Dispatchers.Unconfined
        // path every other test in this file uses
        val realComponentManager: ComponentManager = mockk(relaxed = true)
        every { realComponentManager.doMitm } returns false
        every { realComponentManager.tlsPassthroughCache } returns TlsPassthroughCache()
        // explicit, or the relaxed mock's MitmScope would veto MitM (PKT-24)
        every { realComponentManager.mitmScope } returns MitmScope.ALL
        every { realComponentManager.learnPassthrough } returns true

        val realTransportLayer: TransportLayerConnection = mockk(relaxed = true)
        every { realTransportLayer.remoteHost } returns null
        every { realTransportLayer.remotePort } returns 443
        every { realTransportLayer.appId } returns null

        val connection = TlsConnection(0, realTransportLayer, realComponentManager)

        val recordCount = 50
        val outboundRecords = (0 until recordCount).map { i -> appData(*ByteArray(20) { (i + it).toByte() }) }
        val inboundRecords = (0 until recordCount).map { i -> appData(*ByteArray(20) { (100 + i + it).toByte() }) }

        val outboundReceived = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
        val inboundReceived = java.util.concurrent.CopyOnWriteArrayList<ByteArray>()
        every { realTransportLayer.wrapOutbound(any()) } answers { outboundReceived.add(firstArg<ByteArray>().copyOf()) }
        every { realTransportLayer.wrapInbound(any()) } answers { inboundReceived.add(firstArg<ByteArray>().copyOf()) }

        // each direction's records are sent as two fragments (exercising the reassembly cache),
        // sequentially within their own thread - but the two threads run concurrently against
        // the same connection, exactly like OutboundTrafficHandler/InboundTrafficHandler would
        val outboundThread = Thread {
            outboundRecords.forEach { record ->
                val splitPoint = record.size / 2
                connection.unwrapOutbound(record.copyOfRange(0, splitPoint))
                connection.unwrapOutbound(record.copyOfRange(splitPoint, record.size))
            }
        }
        val inboundThread = Thread {
            inboundRecords.forEach { record ->
                val splitPoint = record.size / 2
                connection.unwrapInbound(record.copyOfRange(0, splitPoint))
                connection.unwrapInbound(record.copyOfRange(splitPoint, record.size))
            }
        }

        outboundThread.start()
        inboundThread.start()
        outboundThread.join(15000)
        inboundThread.join(15000)

        // the two threads above only enqueue work onto connectionScope; wait for it to drain
        val deadline = System.currentTimeMillis() + 15000
        while (System.currentTimeMillis() < deadline &&
            (outboundReceived.size < recordCount || inboundReceived.size < recordCount)
        ) {
            Thread.sleep(20)
        }

        assertEquals("every outbound record must be forwarded exactly once", recordCount, outboundReceived.size)
        assertEquals("every inbound record must be forwarded exactly once", recordCount, inboundReceived.size)

        // exact order + content match proves no interleaving/corruption between concurrently
        // dispatched outbound and inbound work, and no reordering within either direction
        assertEquals(outboundRecords.map { it.toList() }, outboundReceived.map { it.toList() })
        assertEquals(inboundRecords.map { it.toList() }, inboundReceived.map { it.toList() })
    }

    @Test
    fun `closeConnection cancels the connection scope so a late dispatch is dropped instead of running`() {
        val closeConnection = TlsConnection::class.java.getDeclaredMethod("closeConnection")
        closeConnection.isAccessible = true
        closeConnection.invoke(tlsConnection)
        assertEquals("CLOSED", readStateName(tlsConnection))

        // a record arriving after the connection already closed itself - connectionScope was
        // cancelled by closeConnection(), so this dispatch must be dropped, not run against an
        // already-torn-down connection
        tlsConnection.unwrapOutbound(appData(0x01, 0x02, 0x03))

        verify(exactly = 0) { transportLayer.wrapOutbound(any()) }
        assertEquals("CLOSED", readStateName(tlsConnection))
    }
}
