package de.tomcory.heimdall.core.util

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException

object InetAddressUtils {

    /**
     * Converts a string representation of an IPv4 or IPv6 address that specifies a port to an [InetSocketAddress].
     */
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

    /**
     * Converts a string representation of an IPv4 or IPv6 address to an [InetAddress] while ignoring the port.
     */
    @Throws(UnknownHostException::class)
    fun stringToInetAddress(addressString: String): InetAddress {
        val ipAddress = if (addressString.startsWith("[")) {
            // IPv6 with port, e.g., [2001:db8::1]:8080
            addressString.substringAfter("[").substringBefore("]")
        } else {
            // IPv4 or IPv6 without port
            addressString.substringBefore(":")
        }
        return InetAddress.getByName(ipAddress)
    }

    /**
     * Checks if the given string is a valid IP address with a port number.
     */
    fun isValidInetAddressWithPort(input: String): Boolean {
        val ipPortRegex = Regex("^(.*):([0-9]+)$")

        val matchResult = ipPortRegex.matchEntire(input) ?: return false
        val (ipAddress, portString) = matchResult.destructured

        val port = portString.toIntOrNull() ?: return false
        if (port !in 0..65535) return false

        return try {
            InetAddress.getByName(ipAddress) // This will validate the IP address
            true
        } catch (e: Exception) {
            false
        }
    }
}