package de.tomcory.heimdall.core.vpn.metadata

import timber.log.Timber
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Per-VPN-session record of (app, hostname) pairs whose TLS connections must not be MitM'd,
 * because the app has shown it won't accept Heimdall's forged certificate (see
 * [recordFailure] and docs/vpn-mitm-audit.md PKT-23).
 *
 * @param maxSize Upper bound on both the passthrough entries and the pending suspect counters;
 * the least recently used entries are evicted beyond it.
 * @param closedWithoutDataThreshold How many [PassthroughReason.CLOSED_WITHOUT_DATA] hits a pair
 * needs before it is marked for passthrough. That signal is a heuristic (preconnects and idle
 * keep-alive connections also close without sending data), so a single hit isn't enough.
 */
class TlsPassthroughCache(
    private val maxSize: Int = 1000,
    private val closedWithoutDataThreshold: Int = 2
) {

    init {
        Timber.d("TlsPassthroughCache initialised with maxSize=$maxSize")
    }

    private val cache = boundedMap<Boolean>()

    /** Number of [PassthroughReason.CLOSED_WITHOUT_DATA] hits so far for pairs not yet marked for passthrough. */
    private val suspectCounts = boundedMap<Int>()

    /**
     * Pairs that have carried application data through the MitM, see [recordDecrypted]. The
     * value is unused; a map keeps the same bound and eviction as the others.
     */
    private val decrypted = boundedMap<Boolean>()

    /** Pairs whose HTTP/3 the QUIC block policy has blocked, see [recordQuicBlocked]. The value is unused. */
    private val quicBlocked = boundedMap<Boolean>()

    private val lock = ReentrantReadWriteLock()

    private fun <V> boundedMap() = object : LinkedHashMap<TlsPassthroughCacheEntry, V>(maxSize + 1, .75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<TlsPassthroughCacheEntry, V>?): Boolean {
            return size > maxSize
        }
    }

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

    /**
     * Records a client-side MitM failure for the given pair. [PassthroughReason.CLIENT_HANDSHAKE_ERROR]
     * and [PassthroughReason.CLIENT_CLOSED_DURING_HANDSHAKE] mark the pair for passthrough
     * immediately; [PassthroughReason.CLOSED_WITHOUT_DATA] only once it has been seen
     * [closedWithoutDataThreshold] times.
     *
     * @return true if this call newly marked the pair for passthrough, false if it was already
     * marked or hasn't reached the threshold yet.
     */
    fun recordFailure(initiator: Int, hostname: String, reason: PassthroughReason): Boolean {
        val key = TlsPassthroughCacheEntry(initiator, hostname)
        return lock.write {
            if (cache[key] != null) {
                return@write false
            }
            if (reason == PassthroughReason.CLOSED_WITHOUT_DATA && decrypted[key] != null) {
                // the app has already sent data through the MitM for this host, so it accepts
                // the certificate; this was an idle connection (docs/vpn-mitm-audit.md PKT-54)
                return@write false
            }
            if (reason == PassthroughReason.CLOSED_WITHOUT_DATA) {
                val hits = (suspectCounts[key] ?: 0) + 1
                if (hits < closedWithoutDataThreshold) {
                    suspectCounts[key] = hits
                    return@write false
                }
            }
            suspectCounts.remove(key)
            cache[key] = true
            true
        }
    }

    /**
     * Records that a MitM'd connection of the pair has carried application data from the client,
     * which proves that the app accepts Heimdall's certificate for the host. From then on,
     * [PassthroughReason.CLOSED_WITHOUT_DATA] is ignored for the pair, and hits counted before are
     * dropped: apps keep idle connections (pools, pre-connects, the loser of a TCP/QUIC race) and
     * close them without data, which is not a rejection (docs/vpn-mitm-audit.md PKT-54). The
     * other reasons are direct evidence of a rejection and still count.
     */
    fun recordDecrypted(initiator: Int, hostname: String) {
        val key = TlsPassthroughCacheEntry(initiator, hostname)
        lock.write {
            decrypted[key] = true
            suspectCounts.remove(key)
        }
    }

    /**
     * Records that the QUIC block policy blocked HTTP/3 for the pair (docs/vpn-mitm-audit.md
     * PKT-52), so the client was forced onto a TLS fallback.
     */
    fun recordQuicBlocked(initiator: Int, hostname: String) {
        lock.write {
            quicBlocked[TlsPassthroughCacheEntry(initiator, hostname)] = true
        }
    }

    /** Whether [recordQuicBlocked] was called for the pair (and the entry has not been evicted). */
    fun wasQuicBlocked(initiator: Int, hostname: String): Boolean {
        // the write lock, because a read reorders an access-order LinkedHashMap (see get())
        return lock.write {
            quicBlocked[TlsPassthroughCacheEntry(initiator, hostname)] != null
        }
    }
}

/**
 * Client-side signals that an app won't accept Heimdall's forged certificate for a host.
 */
enum class PassthroughReason {
    /** The client-facing TLS handshake failed on data sent by the client, e.g. a fatal alert such as certificate_unknown. */
    CLIENT_HANDSHAKE_ERROR,

    /** The client closed or reset the TCP connection while the client-facing handshake was still running. */
    CLIENT_CLOSED_DURING_HANDSHAKE,

    /** The client completed the handshake, then closed without sending any application data (typical of certificate pinning). */
    CLOSED_WITHOUT_DATA
}

data class TlsPassthroughCacheEntry(val initiator: Int, val hostname: String)
