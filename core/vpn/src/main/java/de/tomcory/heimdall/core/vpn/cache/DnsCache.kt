package de.tomcory.heimdall.core.vpn.cache

import java.util.LinkedHashMap

class DnsCache {
    private val hosts: LinkedHashMap<String?, String?> = object : LinkedHashMap<String?, String?>(MAX_SIZE) {
        override fun removeEldestEntry(eldest: Map.Entry<String?, String?>): Boolean {
            return size >= MAX_SIZE
        }
    }

    companion object {
        private const val MAX_SIZE = 128

        //the singleton
        private val cache = DnsCache()
        @JvmStatic
        fun findHost(ipAddress: String): String? {
            return cache.hosts[ipAddress]
        }

        fun addHost(ipAddress: String, hostname: String) {
            cache.hosts[ipAddress] = hostname
        }
    }
}