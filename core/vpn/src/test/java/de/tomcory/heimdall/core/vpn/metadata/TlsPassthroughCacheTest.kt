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
}
