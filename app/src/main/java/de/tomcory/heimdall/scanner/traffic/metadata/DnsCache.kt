package de.tomcory.heimdall.scanner.traffic.metadata

import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

data class DnsCacheRecord(val hostname: String, val expiry: Long)

object DnsCache {
    private const val maxSize = 1000
    private const val defaultTtl = 60L // TTL in seconds

    private val cache = object : LinkedHashMap<String, DnsCacheRecord>(maxSize + 1, .75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, DnsCacheRecord>?): Boolean {
            return size > maxSize || (eldest?.value?.expiry ?: 0) < System.currentTimeMillis()
        }
    }

    private val lock = ReentrantReadWriteLock()

    fun put(ip: String, hostname: String, ttl: Long = defaultTtl) {
        lock.write {
            cache[ip] = DnsCacheRecord(hostname, System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttl))
        }
    }

    fun get(ip: String): String? {
        return lock.read {
            cache[ip]?.let {
                if (it.expiry < System.currentTimeMillis()) {
                    cache.remove(ip)?.hostname
                } else {
                    it.hostname
                }
            }
        }
    }
}
