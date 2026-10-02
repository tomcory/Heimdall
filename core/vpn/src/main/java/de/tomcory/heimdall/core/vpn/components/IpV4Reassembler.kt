package de.tomcory.heimdall.core.vpn.components

import org.pcap4j.packet.IpV4Packet
import org.pcap4j.util.IpV4Helper
import timber.log.Timber
import java.net.Inet4Address
import java.util.TreeMap

/**
 * Puts IPv4 fragments from the device back together (docs/vpn-mitm-audit.md PKT-46). An app that
 * sends a UDP datagram larger than the tunnel's MTU has it split by the device's IP stack, and
 * only the first fragment carries the UDP header. Without reassembly none of the fragments can
 * be attributed to a connection, and the datagram is lost.
 *
 * Not thread-safe: it is used by the one thread that reads packets from the device.
 *
 * @param timeoutMs How long an incomplete datagram is kept. The fragments of a datagram leave
 * the device back to back, so anything still incomplete after this long will stay that way.
 * @param maxPending How many incomplete datagrams are kept at once; beyond that the oldest is dropped.
 * @param now Injectable for testing; defaults to the real current time.
 */
internal class IpV4Reassembler(
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    private val maxPending: Int = DEFAULT_MAX_PENDING,
    private val now: () -> Long = System::currentTimeMillis
) {

    /** What identifies the fragments of one datagram (RFC 791). */
    private data class Key(val source: Inet4Address, val destination: Inet4Address, val identification: Short, val protocol: Byte)

    private class Pending(val startedAt: Long) {
        /** The fragments received so far, by the offset of their data in the datagram. */
        val fragments = TreeMap<Int, IpV4Packet>()

        /** The length of the datagram's data, known once the last fragment has arrived; -1 until then. */
        var totalLength = -1
    }

    // insertion-ordered, so that the first entry is the oldest
    private val pending = LinkedHashMap<Key, Pending>()

    /** The number of datagrams that are still incomplete. */
    val pendingCount: Int
        get() = pending.size

    /**
     * Takes in one fragment.
     *
     * @return the whole datagram if this fragment completed it, as a packet that is no longer
     * fragmented, or null if fragments are still missing or the fragment had to be discarded.
     */
    fun add(fragment: IpV4Packet): IpV4Packet? {
        val header = fragment.header
        val currentTime = now()
        dropExpired(currentTime)

        val offset = header.fragmentOffset * 8
        val length = fragment.payload?.rawData?.size ?: 0
        if (length == 0 || offset + length > MAX_DATAGRAM_LENGTH) {
            return null
        }

        val key = Key(header.srcAddr, header.dstAddr, header.identification, header.protocol.value())
        val entry = pending.getOrPut(key) {
            if (pending.size >= maxPending) {
                val oldest = pending.keys.first()
                pending.remove(oldest)
                Timber.w("Too many incomplete datagrams, dropping the fragments of the oldest one")
            }
            Pending(currentTime)
        }

        // a fragment that was received already (same offset) is not needed again
        entry.fragments.putIfAbsent(offset, fragment)
        if (!header.moreFragmentFlag) {
            entry.totalLength = offset + length
        }

        if (!isComplete(entry)) {
            return null
        }
        pending.remove(key)
        return try {
            IpV4Helper.defragment(ArrayList(entry.fragments.values))
        } catch (e: Exception) {
            Timber.w("Could not reassemble a fragmented datagram: ${e.message}")
            null
        }
    }

    /** Whether the fragments cover the datagram from its first byte to its last, without gaps or overlaps. */
    private fun isComplete(entry: Pending): Boolean {
        if (entry.totalLength < 0) {
            return false
        }
        var expectedOffset = 0
        for ((offset, fragment) in entry.fragments) {
            if (offset != expectedOffset) {
                return false
            }
            expectedOffset += fragment.payload.rawData.size
        }
        return expectedOffset == entry.totalLength
    }

    private fun dropExpired(currentTime: Long) {
        val iterator = pending.entries.iterator()
        while (iterator.hasNext()) {
            // oldest first, so the first one that has not expired ends the search
            if (currentTime - iterator.next().value.startedAt <= timeoutMs) {
                break
            }
            iterator.remove()
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 5000L
        const val DEFAULT_MAX_PENDING = 64

        /** The most data an IPv4 packet can carry behind a 20-byte header. */
        const val MAX_DATAGRAM_LENGTH = 65515

        /** Whether the packet is one fragment of a larger datagram. */
        fun isFragment(packet: IpV4Packet): Boolean {
            return packet.header.moreFragmentFlag || packet.header.fragmentOffset.toInt() != 0
        }
    }
}
