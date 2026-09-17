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
}
