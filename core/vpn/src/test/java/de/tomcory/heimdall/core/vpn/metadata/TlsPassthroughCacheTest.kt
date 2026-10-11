package de.tomcory.heimdall.core.vpn.metadata

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class TlsPassthroughCacheTest {

    private lateinit var cache: TlsPassthroughCache

    @Before
    fun setup() {
        cache = TlsPassthroughCache()
    }

    @Test
    fun `get returns false before put`() {
        assertFalse(cache.get(1000, "example.com"))
    }

    @Test
    fun `get returns true after put`() {
        cache.put(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        assertTrue(cache.get(1000, "example.com"))
    }

    @Test
    fun `different initiator same hostname returns false`() {
        cache.put(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        assertFalse(cache.get(2000, "example.com"))
    }

    @Test
    fun `same initiator different hostname returns false`() {
        cache.put(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        assertFalse(cache.get(1000, "other.com"))
    }

    @Test
    fun `multiple entries coexist independently`() {
        cache.put(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        cache.put(1000, "google.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        cache.put(2000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)

        assertTrue(cache.get(1000, "example.com"))
        assertTrue(cache.get(1000, "google.com"))
        assertTrue(cache.get(2000, "example.com"))
        assertFalse(cache.get(2000, "google.com"))
    }

    @Test
    fun `inserting more than maxSize evicts the oldest entries`() {
        val bounded = TlsPassthroughCache(maxSize = 3)

        bounded.put(1, "a.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        bounded.put(2, "b.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        bounded.put(3, "c.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        bounded.put(4, "d.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)

        assertFalse("oldest entry should have been evicted", bounded.get(1, "a.com"))
        assertTrue(bounded.get(2, "b.com"))
        assertTrue(bounded.get(3, "c.com"))
        assertTrue(bounded.get(4, "d.com"))
    }

    @Test
    fun `cache never grows past maxSize regardless of how many entries are inserted`() {
        val bounded = TlsPassthroughCache(maxSize = 5)

        for (i in 0 until 1000) {
            bounded.put(i, "host$i.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        }

        val field = TlsPassthroughCache::class.java.getDeclaredField("cache")
        field.isAccessible = true
        val backingMap = field.get(bounded) as Map<*, *>
        assertEquals(5, backingMap.size)
    }

    // ---- recordFailure (docs/records/vpn-mitm-audit.md PKT-23) ----

    @Test
    fun `handshake error marks the pair immediately`() {
        assertTrue(cache.recordFailure(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR))
        assertTrue(cache.get(1000, "example.com"))
    }

    @Test
    fun `close during handshake marks the pair immediately`() {
        assertTrue(cache.recordFailure(1000, "example.com", PassthroughReason.CLIENT_CLOSED_DURING_HANDSHAKE))
        assertTrue(cache.get(1000, "example.com"))
    }

    @Test
    fun `closed without data only marks the pair once the threshold is reached`() {
        val thresholded = TlsPassthroughCache(closedWithoutDataThreshold = 3)

        assertFalse(thresholded.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertFalse(thresholded.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertFalse(thresholded.get(1000, "example.com"))

        assertTrue(thresholded.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertTrue(thresholded.get(1000, "example.com"))
    }

    @Test
    fun `default closed-without-data threshold is two`() {
        assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertTrue(cache.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
    }

    @Test
    fun `closed-without-data hits are counted per pair`() {
        assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertFalse(cache.recordFailure(2000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertFalse(cache.recordFailure(1000, "other.com", PassthroughReason.CLOSED_WITHOUT_DATA))

        assertFalse(cache.get(1000, "example.com"))
        assertFalse(cache.get(2000, "example.com"))
        assertFalse(cache.get(1000, "other.com"))
    }

    @Test
    fun `recordFailure returns false for a pair that is already marked`() {
        cache.put(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR))
        assertTrue(cache.get(1000, "example.com"))
    }

    @Test
    fun `a stronger signal marks a pair that already has closed-without-data hits`() {
        assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertTrue(cache.recordFailure(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR))
        assertEquals("marking a pair clears its pending suspect counter", 0, suspectCounts(cache).size)
    }

    @Test
    fun `pending suspect counters never grow past maxSize`() {
        val bounded = TlsPassthroughCache(maxSize = 5)

        for (i in 0 until 1000) {
            bounded.recordFailure(i, "host$i.com", PassthroughReason.CLOSED_WITHOUT_DATA)
        }

        assertEquals(5, suspectCounts(bounded).size)
    }

    // ---- docs/records/vpn-mitm-audit.md PKT-56: upstream failures and stored reasons ----

    @Test
    fun `an upstream handshake failure marks the pair at once`() {
        assertTrue(cache.recordFailure(1000, "example.com", PassthroughReason.UPSTREAM_HANDSHAKE_FAILED))
        assertTrue(cache.get(1000, "example.com"))
    }

    @Test
    fun `the reason a pair was marked for is stored`() {
        assertNull(cache.getReason(1000, "example.com"))

        cache.recordFailure(1000, "example.com", PassthroughReason.UPSTREAM_HANDSHAKE_FAILED)
        cache.recordFailure(1000, "pinned.com", PassthroughReason.CLOSED_WITHOUT_DATA)
        cache.recordFailure(1000, "pinned.com", PassthroughReason.CLOSED_WITHOUT_DATA)

        assertEquals(PassthroughReason.UPSTREAM_HANDSHAKE_FAILED, cache.getReason(1000, "example.com"))
        assertEquals(PassthroughReason.CLOSED_WITHOUT_DATA, cache.getReason(1000, "pinned.com"))
    }

    @Test
    fun `a later failure does not replace the reason a pair was marked for`() {
        cache.recordFailure(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR)
        assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.UPSTREAM_HANDSHAKE_FAILED))
        assertEquals(PassthroughReason.CLIENT_HANDSHAKE_ERROR, cache.getReason(1000, "example.com"))
    }

    // ---- docs/records/vpn-mitm-audit.md PKT-54: idle closes after data was decrypted ----

    @Test
    fun `closed-without-data never marks a pair that has carried data`() {
        cache.recordDecrypted(1000, "example.com")

        repeat(5) {
            assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        }
        assertFalse(cache.get(1000, "example.com"))
        assertEquals(0, suspectCounts(cache).size)
    }

    @Test
    fun `carrying data drops closed-without-data hits counted before`() {
        assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        cache.recordDecrypted(1000, "example.com")
        assertEquals(0, suspectCounts(cache).size)

        assertFalse(cache.recordFailure(1000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        assertFalse(cache.get(1000, "example.com"))
    }

    @Test
    fun `a rejection still marks a pair that has carried data`() {
        cache.recordDecrypted(1000, "example.com")
        assertTrue(cache.recordFailure(1000, "example.com", PassthroughReason.CLIENT_HANDSHAKE_ERROR))
        assertTrue(cache.get(1000, "example.com"))
    }

    @Test
    fun `carrying data is recorded per pair`() {
        cache.recordDecrypted(1000, "example.com")

        cache.recordFailure(2000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA)
        assertTrue(cache.recordFailure(2000, "example.com", PassthroughReason.CLOSED_WITHOUT_DATA))
        cache.recordFailure(1000, "other.com", PassthroughReason.CLOSED_WITHOUT_DATA)
        assertTrue(cache.recordFailure(1000, "other.com", PassthroughReason.CLOSED_WITHOUT_DATA))
    }

    @Test
    fun `pairs that carried data never grow past maxSize`() {
        val bounded = TlsPassthroughCache(maxSize = 5)

        for (i in 0 until 1000) {
            bounded.recordDecrypted(i, "host$i.com")
        }

        val field = TlsPassthroughCache::class.java.getDeclaredField("decrypted")
        field.isAccessible = true
        assertEquals(5, (field.get(bounded) as Map<*, *>).size)
    }

    @Test
    fun `a blocked QUIC pair is remembered per pair and bounded`() {
        assertFalse(cache.wasQuicBlocked(1000, "example.com"))
        cache.recordQuicBlocked(1000, "example.com")
        assertTrue(cache.wasQuicBlocked(1000, "example.com"))
        assertFalse(cache.wasQuicBlocked(2000, "example.com"))
        assertFalse(cache.wasQuicBlocked(1000, "other.com"))

        val bounded = TlsPassthroughCache(maxSize = 5)
        for (i in 0 until 1000) {
            bounded.recordQuicBlocked(i, "host$i.com")
        }
        assertTrue(bounded.wasQuicBlocked(999, "host999.com"))
        assertFalse(bounded.wasQuicBlocked(0, "host0.com"))
    }

    private fun suspectCounts(target: TlsPassthroughCache): Map<*, *> {
        val field = TlsPassthroughCache::class.java.getDeclaredField("suspectCounts")
        field.isAccessible = true
        return field.get(target) as Map<*, *>
    }
}
