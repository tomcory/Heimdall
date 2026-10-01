package de.tomcory.heimdall.core.vpn.connection.appLayer

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Tests for [ChunkedBodyTracker] (docs/vpn-mitm-audit.md PKT-32).
 */
class ChunkedBodyTrackerTest {

    private fun bytes(text: String) = text.toByteArray(Charsets.US_ASCII)

    @Test
    fun `finds the end of a complete body`() {
        val body = bytes("5\r\nhello\r\n0\r\n\r\n")
        val tracker = ChunkedBodyTracker()

        assertEquals(body.size, tracker.feed(body))
        assertEquals(5L, tracker.bodyLength)
    }

    @Test
    fun `reports the end index when more bytes follow the body`() {
        val body = bytes("5\r\nhello\r\n0\r\n\r\n")
        val tracker = ChunkedBodyTracker()

        assertEquals(body.size, tracker.feed(body + bytes("HTTP/1.1 200 OK\r\n")))
    }

    @Test
    fun `starts at the given offset`() {
        val headers = bytes("HTTP/1.1 200 OK\r\n\r\n")
        val body = bytes("3\r\nabc\r\n0\r\n\r\n")
        val tracker = ChunkedBodyTracker()

        assertEquals(headers.size + body.size, tracker.feed(headers + body, headers.size))
        assertEquals(3L, tracker.bodyLength)
    }

    @Test
    fun `an empty body is just the zero-size chunk and the empty line`() {
        val tracker = ChunkedBodyTracker()

        assertEquals(5, tracker.feed(bytes("0\r\n\r\n")))
        assertEquals(0L, tracker.bodyLength)
    }

    @Test
    fun `the zero-size chunk without the final empty line is incomplete`() {
        val tracker = ChunkedBodyTracker()

        assertEquals(ChunkedBodyTracker.INCOMPLETE, tracker.feed(bytes("5\r\nhello\r\n0\r\n")))
        assertEquals(2, tracker.feed(bytes("\r\n")))
    }

    @Test
    fun `keeps its place across payloads split at every position`() {
        val body = bytes("5\r\nhello\r\na;ext=1\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\n")

        for (split in 1 until body.size) {
            val tracker = ChunkedBodyTracker()
            val first = tracker.feed(body.copyOf(split))
            assertEquals("split at $split", ChunkedBodyTracker.INCOMPLETE, first)
            assertEquals("split at $split", body.size - split, tracker.feed(body.copyOfRange(split, body.size)))
            assertEquals(15L, tracker.bodyLength)
        }
    }

    @Test
    fun `chunk data that looks like a terminator is skipped by its declared size`() {
        val body = bytes("5\r\n0\r\n\r\n\r\n0\r\n\r\n")
        val tracker = ChunkedBodyTracker()

        assertEquals(body.size, tracker.feed(body))
        assertEquals(5L, tracker.bodyLength)
    }

    @Test
    fun `trailer lines are skipped until the empty line`() {
        val body = bytes("0\r\nA: 1\r\nB: 2\r\n\r\n")
        val tracker = ChunkedBodyTracker()

        assertEquals(body.size, tracker.feed(body))
    }

    @Test
    fun `sizes are hexadecimal and case-insensitive`() {
        val data = "x".repeat(0x1F)
        val tracker = ChunkedBodyTracker()

        assertEquals(ChunkedBodyTracker.INCOMPLETE, tracker.feed(bytes("1f\r\n$data\r\n1F\r\n$data\r\n")))
        assertEquals(62L, tracker.bodyLength)
    }

    @Test
    fun `a size that is not hexadecimal is malformed`() {
        assertEquals(ChunkedBodyTracker.MALFORMED, ChunkedBodyTracker().feed(bytes("zz\r\nhello\r\n")))
        assertEquals(ChunkedBodyTracker.MALFORMED, ChunkedBodyTracker().feed(bytes("\r\nhello\r\n")))
        assertEquals(ChunkedBodyTracker.MALFORMED, ChunkedBodyTracker().feed(bytes("-5\r\nhello\r\n")))
    }

    @Test
    fun `chunk data that is not followed by CRLF is malformed`() {
        assertEquals(ChunkedBodyTracker.MALFORMED, ChunkedBodyTracker().feed(bytes("5\r\nhelloXX0\r\n\r\n")))
    }

    @Test
    fun `an endless size line is malformed`() {
        assertEquals(ChunkedBodyTracker.MALFORMED, ChunkedBodyTracker().feed(ByteArray(5000) { 'a'.code.toByte() }))
    }

    @Test
    fun `stays malformed until reset`() {
        val tracker = ChunkedBodyTracker()
        assertEquals(ChunkedBodyTracker.MALFORMED, tracker.feed(bytes("zz\r\n")))
        assertEquals(ChunkedBodyTracker.MALFORMED, tracker.feed(bytes("0\r\n\r\n")))

        tracker.reset()

        assertEquals(5, tracker.feed(bytes("0\r\n\r\n")))
        assertEquals(0L, tracker.bodyLength)
    }
}
