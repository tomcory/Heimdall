package de.tomcory.heimdall.core.vpn.metadata

import timber.log.Timber
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

class TlsPassthroughCache(
    private val maxSize: Int = 1000
) {

    init {
        Timber.d("TlsPassthroughCache initialised with maxSize=$maxSize")
    }

    private val cache = object : LinkedHashMap<TlsPassthroughCacheEntry, Boolean>(maxSize + 1, .75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<TlsPassthroughCacheEntry, Boolean>?): Boolean {
            return size > maxSize
        }
    }

    private val lock = ReentrantReadWriteLock()

    fun put(initiator: Int, hostname: String) {
        lock.write {
            cache[TlsPassthroughCacheEntry(initiator, hostname)] = true
        }
    }

    fun get(initiator: Int, hostname: String): Boolean {
        // an access-order LinkedHashMap reorders its internal list on reads too (to track
        // recency for eviction), so this needs the write lock just like put() does
        return lock.write {
            cache[TlsPassthroughCacheEntry(initiator, hostname)] != null
        }
    }
}

data class TlsPassthroughCacheEntry(val initiator: Int, val hostname: String)