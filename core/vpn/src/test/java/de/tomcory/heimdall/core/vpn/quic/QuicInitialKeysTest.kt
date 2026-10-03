package de.tomcory.heimdall.core.vpn.quic

import de.tomcory.heimdall.core.vpn.integration.support.QuicRfcVectors
import de.tomcory.heimdall.core.vpn.integration.support.QuicRfcVectors.bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * docs/vpn-mitm-audit.md PKT-49: the Initial keys, checked against RFC 9001 Appendix A.1 and
 * RFC 9369 Appendix A.1.
 */
class QuicInitialKeysTest {

    private val dcid = bytes(QuicRfcVectors.DCID)

    @Test
    fun `version 1 keys match RFC 9001`() {
        val v = QuicRfcVectors.V1
        val initialSecret = QuicInitialKeys.initialSecret(QuicInitialKeys.VERSION_1, dcid)!!
        assertArrayEquals(bytes(v.INITIAL_SECRET), initialSecret)
        assertArrayEquals(bytes(v.CLIENT_SECRET), QuicInitialKeys.expandLabel(initialSecret, "client in", 32))
        assertArrayEquals(bytes(v.SERVER_SECRET), QuicInitialKeys.expandLabel(initialSecret, "server in", 32))

        val client = QuicInitialKeys.forClient(QuicInitialKeys.VERSION_1, dcid)!!
        assertArrayEquals(bytes(v.CLIENT_KEY), client.key)
        assertArrayEquals(bytes(v.CLIENT_IV), client.iv)
        assertArrayEquals(bytes(v.CLIENT_HP), client.hp)

        val server = QuicInitialKeys.forServer(QuicInitialKeys.VERSION_1, dcid)!!
        assertArrayEquals(bytes(v.SERVER_KEY), server.key)
        assertArrayEquals(bytes(v.SERVER_IV), server.iv)
        assertArrayEquals(bytes(v.SERVER_HP), server.hp)
    }

    @Test
    fun `version 2 keys match RFC 9369`() {
        val v = QuicRfcVectors.V2
        val initialSecret = QuicInitialKeys.initialSecret(QuicInitialKeys.VERSION_2, dcid)!!
        assertArrayEquals(bytes(v.INITIAL_SECRET), initialSecret)
        assertArrayEquals(bytes(v.CLIENT_SECRET), QuicInitialKeys.expandLabel(initialSecret, "client in", 32))

        val client = QuicInitialKeys.forClient(QuicInitialKeys.VERSION_2, dcid)!!
        assertArrayEquals(bytes(v.CLIENT_KEY), client.key)
        assertArrayEquals(bytes(v.CLIENT_IV), client.iv)
        assertArrayEquals(bytes(v.CLIENT_HP), client.hp)

        val server = QuicInitialKeys.forServer(QuicInitialKeys.VERSION_2, dcid)!!
        assertArrayEquals(bytes(v.SERVER_KEY), server.key)
        assertArrayEquals(bytes(v.SERVER_IV), server.iv)
        assertArrayEquals(bytes(v.SERVER_HP), server.hp)
    }

    @Test
    fun `an unknown version has no keys`() {
        assertNull(QuicInitialKeys.forClient(0x0a0a0a0a, dcid))
        assertNull(QuicInitialKeys.forClient(0xff00001d.toInt(), dcid)) // draft-29
        assertFalse(QuicInitialKeys.isSupported(0))
        assertTrue(QuicInitialKeys.isSupported(QuicInitialKeys.VERSION_1))
        assertTrue(QuicInitialKeys.isSupported(QuicInitialKeys.VERSION_2))
    }
}
