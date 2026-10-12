package de.tomcory.heimdall.core.vpn.rules

import de.tomcory.heimdall.core.util.Trie

/**
 * Matches hostnames against a list of entries, as domain suffixes: `example.com` also matches
 * `api.example.com` (but not `badexample.com`). Case, a trailing dot and a leading `*.` in an
 * entry are ignored. An entry that is an IP address matches that address only.
 */
class HostMatcher(entries: List<String>) {

    private val normalised = entries.map(::normalise).filter { it.isNotEmpty() }

    private val trie = Trie<String> { it.split(".").reversed() }.apply {
        normalised.forEach { insert(it, it) }
    }

    /** IPv6 literals contain no dots, so the suffix trie cannot hold them. */
    private val literals = normalised.filter { ':' in it }.toSet()

    val isEmpty: Boolean get() = normalised.isEmpty()

    /** @param hostname A hostname or an IP address. An empty one never matches. */
    fun matches(hostname: String): Boolean {
        val host = normalise(hostname)
        return host.isNotEmpty() && (host in literals || trie.search(host) != null)
    }

    companion object {
        fun normalise(host: String) = host.trim().lowercase().removePrefix("*.").removeSuffix(".")
    }
}
