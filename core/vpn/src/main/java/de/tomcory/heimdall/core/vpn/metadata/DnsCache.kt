package de.tomcory.heimdall.core.vpn.metadata

import timber.log.Timber
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

data class DnsCacheRecord(val hostname: String, val expiry: Long)

class DnsCache(
    private val maxSize: Int = 1000,
    private val defaultTtl: Long = 60L
) {

    init {
        Timber.d("DnsCache initialised with maxSize=$maxSize and defaultTtl=$defaultTtl")
    }

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
