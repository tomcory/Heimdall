package de.tomcory.heimdall.scanner.traffic.cache

import java.util.LinkedHashMap

class DnsCache {
    private val hosts: LinkedHashMap<String?, String?> = object : LinkedHashMap<String?, String?>(
        de.tomcory.heimdall.scanner.traffic.cache.DnsCache.Companion.MAX_SIZE
    ) {
        override fun removeEldestEntry(eldest: Map.Entry<String?, String?>): Boolean {
            return size >= de.tomcory.heimdall.scanner.traffic.cache.DnsCache.Companion.MAX_SIZE
        }
    }

    companion object {
        private const val MAX_SIZE = 128

        //the singleton
        private val cache = de.tomcory.heimdall.scanner.traffic.cache.DnsCache()
        @JvmStatic
        fun findHost(ipAddress: String): String? {
            return de.tomcory.heimdall.scanner.traffic.cache.DnsCache.Companion.cache.hosts[ipAddress]
        }

        fun addHost(ipAddress: String, hostname: String) {
            de.tomcory.heimdall.scanner.traffic.cache.DnsCache.Companion.cache.hosts[ipAddress] = hostname
        }
    }
}