package de.tomcory.heimdall.core.vpn.metadata

import timber.log.Timber
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

class TlsPassthroughCache {

    init {
        Timber.d("TlsPassthroughCache initialised")
    }

    private val cache = HashSet<TlsPassthroughCacheEntry>()

    private val lock = ReentrantReadWriteLock()

    fun put(initiator: Int, hostname: String) {
        lock.write {
            cache.add(TlsPassthroughCacheEntry(initiator, hostname))
        }
    }

    fun get(initiator: Int, hostname: String): Boolean {
        return lock.read {
            cache.contains(TlsPassthroughCacheEntry(initiator, hostname))
        }
    }
}

data class TlsPassthroughCacheEntry(val initiator: Int, val hostname: String)