package de.tomcory.heimdall.core.vpn.quic

import de.tomcory.heimdall.core.vpn.integration.support.QuicRfcVectors.bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** docs/vpn-mitm-audit.md PKT-49: QUIC variable-length integers, with the examples of RFC 9000 appendix A.1. */
class QuicVarIntTest {

    @Test
    fun `decodes the examples of RFC 9000`() {
        assertEquals(151288809941952652L, QuicVarInt.decode(bytes("c2197c5eff14e88c"), 0))
        assertEquals(494878333L, QuicVarInt.decode(bytes("9d7f3e7d"), 0))
        assertEquals(15293L, QuicVarInt.decode(bytes("7bbd"), 0))
        assertEquals(37L, QuicVarInt.decode(bytes("25"), 0))
        // the same value in a longer form than necessary
        assertEquals(37L, QuicVarInt.decode(bytes("4025"), 0))
    }

    @Test
    fun `reads at an offset and reports the length from the first byte`() {
        val data = bytes("ff7bbd00")
        assertEquals(15293L, QuicVarInt.decode(data, 1))
        assertEquals(2, QuicVarInt.length(data[1]))
        assertEquals(8, QuicVarInt.length(0xc2.toByte()))
        assertEquals(1, QuicVarInt.length(0x25))
    }

    @Test
    fun `a truncated integer decodes to -1`() {
        assertEquals(-1L, QuicVarInt.decode(bytes("9d7f3e"), 0))
        assertEquals(-1L, QuicVarInt.decode(ByteArray(0), 0))
        assertEquals(-1L, QuicVarInt.decode(bytes("25"), 1))
    }

    @Test
    fun `encodes in the shortest form or a given one`() {
        assertArrayEquals(bytes("c2197c5eff14e88c"), QuicVarInt.encode(151288809941952652L))
        assertArrayEquals(bytes("9d7f3e7d"), QuicVarInt.encode(494878333L))
        assertArrayEquals(bytes("7bbd"), QuicVarInt.encode(15293L))
        assertArrayEquals(bytes("25"), QuicVarInt.encode(37L))
        assertArrayEquals(bytes("4025"), QuicVarInt.encode(37L, 2))
        assertArrayEquals(bytes("449e"), QuicVarInt.encode(1182L, 2))
    }
}
