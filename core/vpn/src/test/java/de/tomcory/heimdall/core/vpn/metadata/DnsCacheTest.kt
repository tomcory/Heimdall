package de.tomcory.heimdall.core.vpn.metadata

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class DnsCacheTest {

    private lateinit var cache: DnsCache

    @Before
    fun setup() {
        cache = DnsCache(maxSize = 5, defaultTtl = 60)
    }

    @Test
    fun `put and get returns hostname`() {
        cache.put("1.2.3.4", "example.com", 60)
        assertEquals("example.com", cache.get("1.2.3.4"))
    }

    @Test
    fun `get missing key returns null`() {
        assertNull(cache.get("10.0.0.1"))
    }

    @Test
    fun `put overwrites existing entry`() {
        cache.put("1.2.3.4", "old.com", 60)
        cache.put("1.2.3.4", "new.com", 60)
        assertEquals("new.com", cache.get("1.2.3.4"))
    }

    @Test
    fun `entry is evicted from cache after TTL elapses`() {
        cache.put("1.2.3.4", "example.com", 1)
        Thread.sleep(1500)
        // First get after expiry triggers removal from cache (implementation removes-on-read)
        cache.get("1.2.3.4")
        // Subsequent get returns null since the entry was removed
        assertNull(cache.get("1.2.3.4"))
    }

    @Test
    fun `entry is still present before TTL elapses`() {
        cache.put("1.2.3.4", "example.com", 5)
        Thread.sleep(100)
        assertEquals("example.com", cache.get("1.2.3.4"))
    }

    @Test
    fun `oldest entry evicted when maxSize exceeded`() {
        // fill the cache to capacity (maxSize = 5)
        for (i in 1..5) {
            cache.put("10.0.0.$i", "host$i.com", 60)
        }
        // inserting a 6th entry should evict the oldest
        cache.put("10.0.0.6", "host6.com", 60)
        // oldest entry (10.0.0.1) should be gone
        assertNull(cache.get("10.0.0.1"))
        // newest entry should be present
        assertEquals("host6.com", cache.get("10.0.0.6"))
    }

    @Test
    fun `multiple distinct IPs can be stored`() {
        cache.put("1.1.1.1", "cloudflare.com", 60)
        cache.put("8.8.8.8", "google.com", 60)
        assertEquals("cloudflare.com", cache.get("1.1.1.1"))
        assertEquals("google.com", cache.get("8.8.8.8"))
    }

    @Test
    fun `concurrent puts and gets do not throw`() {
        val executor = Executors.newFixedThreadPool(8)
        val latch = CountDownLatch(100)
        val errors = mutableListOf<Throwable>()

        repeat(50) { i ->
            executor.execute {
                try {
                    cache.put("192.168.1.$i", "host$i.com", 60)
                } catch (t: Throwable) {
                    synchronized(errors) { errors.add(t) }
                } finally {
                    latch.countDown()
                }
            }
        }
        repeat(50) {
            executor.execute {
                try {
                    cache.get("192.168.1.${it % 50}")
                } catch (t: Throwable) {
                    synchronized(errors) { errors.add(t) }
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()
        assertTrue("Concurrent operations threw: $errors", errors.isEmpty())
    }
}
