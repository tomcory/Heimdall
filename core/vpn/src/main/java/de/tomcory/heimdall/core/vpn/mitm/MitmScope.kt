package de.tomcory.heimdall.core.vpn.mitm

import de.tomcory.heimdall.core.util.Trie

/**
 * Which TLS connections the MitM engine may intercept, as configured by the user's MitM monitoring
 * scope preferences (docs/vpn-mitm-audit.md PKT-24). Connections outside the scope are passed
 * through unmodified. `core:vpn` doesn't depend on the preference schema, so the app module
 * resolves the preferences into this type.
 *
 * @param includedApps If not null, only these packages are intercepted.
 * @param excludedApps Packages that are never intercepted.
 * @param hostMode How [hosts] is applied.
 * @param hosts Hostnames matched as domain suffixes: `example.com` also matches `api.example.com`
 * (but not `badexample.com`). A leading `*.` is ignored.
 */
data class MitmScope(
    val includedApps: Set<String>? = null,
    val excludedApps: Set<String> = emptySet(),
    val hostMode: HostMode = HostMode.ALL,
    val hosts: List<String> = emptyList()
) {

    enum class HostMode {
        /** Intercept every host. */
        ALL,

        /** Only intercept hosts matching [hosts]. */
        WHITELIST,

        /** Intercept every host except those matching [hosts]. */
        BLACKLIST
    }

    private val hostTrie = Trie<String> { it.split(".").reversed() }.apply {
        hosts.map(::normaliseHost).filter { it.isNotEmpty() }.forEach { insert(it, it) }
    }

    /**
     * @param appPackage The package of the app that opened the connection, if known.
     * @param hostname The connection's hostname (SNI, DNS-derived name, or IP address).
     */
    fun shouldIntercept(appPackage: String?, hostname: String): Boolean {
        if (includedApps != null && (appPackage == null || appPackage !in includedApps)) {
            return false
        }
        if (appPackage != null && appPackage in excludedApps) {
            return false
        }
        return when (hostMode) {
            HostMode.ALL -> true
            HostMode.WHITELIST -> matchesHost(hostname)
            HostMode.BLACKLIST -> !matchesHost(hostname)
        }
    }

    private fun matchesHost(hostname: String): Boolean {
        val host = normaliseHost(hostname)
        return host.isNotEmpty() && hostTrie.search(host) != null
    }

    companion object {
        /** Intercept everything (the default when no scope is configured). */
        val ALL = MitmScope()

        private fun normaliseHost(host: String) = host.trim().lowercase().removePrefix("*.").removeSuffix(".")
    }
}
