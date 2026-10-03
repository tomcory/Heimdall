package de.tomcory.heimdall.core.vpn.quic

/**
 * QUIC's variable-length integer encoding (RFC 9000 section 16): the two most significant bits
 * of the first byte give the length (1, 2, 4 or 8 bytes), the remaining bits the value, in
 * network byte order.
 */
object QuicVarInt {

    /** The largest value the encoding can represent, 2^62 - 1. */
    const val MAX_VALUE = (1L shl 62) - 1

    /** The number of bytes of the integer that starts with [firstByte]. */
    fun length(firstByte: Byte): Int = 1 shl ((firstByte.toInt() and 0xFF) ushr 6)

    /**
     * Decodes the integer that starts at [offset].
     *
     * @return the value, or -1 if [data] ends before the integer does.
     */
    fun decode(data: ByteArray, offset: Int): Long {
        if (offset < 0 || offset >= data.size) {
            return -1
        }
        val length = length(data[offset])
        if (offset + length > data.size) {
            return -1
        }
        var value = (data[offset].toLong() and 0x3F)
        for (i in 1 until length) {
            value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
        }
        return value
    }

    /** Encodes [value] in the shortest form that holds it. */
    fun encode(value: Long): ByteArray {
        require(value in 0..MAX_VALUE) { "$value cannot be encoded as a QUIC variable-length integer" }
        val length = when {
            value < (1L shl 6) -> 1
            value < (1L shl 14) -> 2
            value < (1L shl 30) -> 4
            else -> 8
        }
        return encode(value, length)
    }

    /**
     * Encodes [value] in exactly [length] bytes (1, 2, 4 or 8). A longer form than necessary is
     * valid and is what senders use when they write a length before they know it.
     */
    fun encode(value: Long, length: Int): ByteArray {
        val prefix = when (length) {
            1 -> 0
            2 -> 1
            4 -> 2
            8 -> 3
            else -> throw IllegalArgumentException("A QUIC variable-length integer has 1, 2, 4 or 8 bytes, not $length")
        }
        require(value >= 0 && value < (1L shl (length * 8 - 2))) { "$value does not fit into $length bytes" }
        val bytes = ByteArray(length)
        var remaining = value
        for (i in length - 1 downTo 0) {
            bytes[i] = (remaining and 0xFF).toByte()
            remaining = remaining ushr 8
        }
        bytes[0] = (bytes[0].toInt() or (prefix shl 6)).toByte()
        return bytes
    }
}
