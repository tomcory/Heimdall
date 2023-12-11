package de.tomcory.heimdall.core.util

import java.net.InetSocketAddress

object StringUtils {
    fun stringToInetSocketAddress(input: String): InetSocketAddress? {
        val ipAddress: String
        val port: Int

        if (input.startsWith("[")) {
            // IPv6 format: [address]:port
            val lastIndex = input.lastIndexOf("]")
            if (lastIndex == -1) return null

            ipAddress = input.substring(1, lastIndex)
            val portString = input.substring(lastIndex + 2) // Skip "]" and ":"
            port = portString.toIntOrNull() ?: return null
        } else {
            // IPv4 format: address:port
            val parts = input.split(":")
            if (parts.size != 2) return null

            ipAddress = parts[0]
            port = parts[1].toIntOrNull() ?: return null
        }

        return try {
            InetSocketAddress(ipAddress, port)
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}