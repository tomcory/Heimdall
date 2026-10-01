package de.tomcory.heimdall.core.vpn.connection.appLayer

/**
 * Follows an HTTP/1.1 chunked message body (RFC 9112 section 7.1) across the payloads it
 * arrives in, to find where it ends (docs/vpn-mitm-audit.md PKT-32).
 *
 * A chunked body is a series of chunks, each a size line in hex followed by that many bytes and
 * a CRLF. It ends with a zero-size chunk, an optional trailer section and an empty line:
 *
 * ```
 * 5\r\nhello\r\n
 * 0\r\n
 * \r\n
 * ```
 *
 * The end can only be found by honouring the declared sizes: chunk data may contain any bytes,
 * including sequences that look like a terminator. The tracker reads every byte once and keeps
 * no copy of the body, so it also works for bodies that are too large to keep.
 */
internal class ChunkedBodyTracker {

    private enum class Phase {
        /** Reading a chunk-size line, up to its LF. */
        SIZE_LINE,

        /** Skipping the declared number of chunk-data bytes. */
        DATA,

        /** Skipping the CRLF that follows a chunk's data. */
        DATA_END,

        /** After the zero-size chunk: reading trailer lines until an empty one. */
        TRAILERS,

        DONE,
        MALFORMED
    }

    private var phase = Phase.SIZE_LINE

    /** The size line read so far, without its line ending. */
    private val sizeLine = StringBuilder()

    /** Bytes left in the current phase: chunk data in [Phase.DATA], line ending in [Phase.DATA_END]. */
    private var remaining = 0L

    /** Length of the current trailer line so far, not counting its line ending. */
    private var trailerLineLength = 0

    /** Total number of chunk-data bytes seen so far, i.e. the size of the decoded body. */
    var bodyLength = 0L
        private set

    /**
     * Consumes body bytes from [bytes], starting at [from].
     *
     * @return the index just past the end of the chunked body if it ends within [bytes],
     * [INCOMPLETE] if more bytes are needed, or [MALFORMED] if the bytes are not a valid chunked
     * body. After anything but [INCOMPLETE] the tracker must be [reset] before it is used again.
     */
    fun feed(bytes: ByteArray, from: Int = 0): Int {
        var i = from
        while (i < bytes.size) {
            when (phase) {
                Phase.SIZE_LINE -> {
                    val b = bytes[i++]
                    if (b == LF) {
                        val size = parseSize()
                        when {
                            size == null -> phase = Phase.MALFORMED
                            size == 0L -> {
                                phase = Phase.TRAILERS
                                trailerLineLength = 0
                            }
                            else -> {
                                phase = Phase.DATA
                                remaining = size
                            }
                        }
                        sizeLine.setLength(0)
                    } else if (b != CR) {
                        sizeLine.append(b.toInt().toChar())
                        if (sizeLine.length > MAX_SIZE_LINE_LENGTH) {
                            phase = Phase.MALFORMED
                        }
                    }
                }

                Phase.DATA -> {
                    val take = minOf(remaining, (bytes.size - i).toLong()).toInt()
                    i += take
                    remaining -= take
                    bodyLength += take
                    if (remaining == 0L) {
                        phase = Phase.DATA_END
                        remaining = 2
                    }
                }

                Phase.DATA_END -> {
                    val b = bytes[i++]
                    val expected = if (remaining == 2L) CR else LF
                    if (b != expected) {
                        phase = Phase.MALFORMED
                    } else if (--remaining == 0L) {
                        phase = Phase.SIZE_LINE
                    }
                }

                Phase.TRAILERS -> {
                    val b = bytes[i++]
                    if (b == LF) {
                        if (trailerLineLength == 0) {
                            phase = Phase.DONE
                            return i
                        }
                        trailerLineLength = 0
                    } else if (b != CR) {
                        trailerLineLength++
                    }
                }

                Phase.DONE -> return i
                Phase.MALFORMED -> return MALFORMED
            }
        }
        return when (phase) {
            Phase.MALFORMED -> MALFORMED
            else -> INCOMPLETE
        }
    }

    /** Parses the collected size line: hex digits, optionally followed by `;` and chunk extensions. */
    private fun parseSize(): Long? {
        val digits = sizeLine.toString().substringBefore(';').trim()
        if (digits.isEmpty() || digits.length > MAX_SIZE_DIGITS) {
            return null
        }
        return digits.toLongOrNull(16)?.takeIf { it >= 0 }
    }

    fun reset() {
        phase = Phase.SIZE_LINE
        sizeLine.setLength(0)
        remaining = 0
        trailerLineLength = 0
        bodyLength = 0
    }

    companion object {
        const val INCOMPLETE = -1
        const val MALFORMED = -2

        private const val CR = '\r'.code.toByte()
        private const val LF = '\n'.code.toByte()

        /** A size line is a few hex digits plus rarely-used extensions; anything longer is not one. */
        private const val MAX_SIZE_LINE_LENGTH = 1024

        /** 15 hex digits always fit a positive Long. */
        private const val MAX_SIZE_DIGITS = 15
    }
}
