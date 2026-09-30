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
        cache.put(1000, "example.com")
        assertTrue(cache.get(1000, "example.com"))
    }

    @Test
    fun `different initiator same hostname returns false`() {
        cache.put(1000, "example.com")
        assertFalse(cache.get(2000, "example.com"))
    }

    @Test
    fun `same initiator different hostname returns false`() {
        cache.put(1000, "example.com")
        assertFalse(cache.get(1000, "other.com"))
    }

    @Test
    fun `multiple entries coexist independently`() {
        cache.put(1000, "example.com")
        cache.put(1000, "google.com")
        cache.put(2000, "example.com")

        assertTrue(cache.get(1000, "example.com"))
        assertTrue(cache.get(1000, "google.com"))
        assertTrue(cache.get(2000, "example.com"))
        assertFalse(cache.get(2000, "google.com"))
    }

    @Test
    fun `inserting more than maxSize evicts the oldest entries`() {
        val bounded = TlsPassthroughCache(maxSize = 3)

        bounded.put(1, "a.com")
        bounded.put(2, "b.com")
        bounded.put(3, "c.com")
        bounded.put(4, "d.com")

        assertFalse("oldest entry should have been evicted", bounded.get(1, "a.com"))
        assertTrue(bounded.get(2, "b.com"))
        assertTrue(bounded.get(3, "c.com"))
        assertTrue(bounded.get(4, "d.com"))
    }

    @Test
    fun `cache never grows past maxSize regardless of how many entries are inserted`() {
        val bounded = TlsPassthroughCache(maxSize = 5)

        for (i in 0 until 1000) {
            bounded.put(i, "host$i.com")
        }

        val field = TlsPassthroughCache::class.java.getDeclaredField("cache")
        field.isAccessible = true
        val backingMap = field.get(bounded) as Map<*, *>
        assertEquals(5, backingMap.size)
    }

    // ---- recordFailure (docs/vpn-mitm-audit.md PKT-23) ----

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
        cache.put(1000, "example.com")
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

    private fun suspectCounts(target: TlsPassthroughCache): Map<*, *> {
        val field = TlsPassthroughCache::class.java.getDeclaredField("suspectCounts")
        field.isAccessible = true
        return field.get(target) as Map<*, *>
    }
}
