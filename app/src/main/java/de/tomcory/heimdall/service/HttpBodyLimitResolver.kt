package de.tomcory.heimdall.service

import de.tomcory.heimdall.core.vpn.connection.appLayer.HttpConnection

/**
 * Turns the "largest HTTP body to keep" preference (in KB) into the number of bytes the VPN keeps
 * of each body (docs/records/vpn-mitm-audit.md PKT-59).
 */
object HttpBodyLimitResolver {

    /**
     * @param preferenceKb The stored preference. 0 is what installs from before the preference
     * existed read, so it means the default rather than "keep nothing".
     */
    fun resolve(preferenceKb: Int): Int {
        if (preferenceKb <= 0) {
            return HttpConnection.DEFAULT_MAX_BODY_SIZE
        }
        return (preferenceKb.toLong() * 1024).coerceAtMost(HttpConnection.MAX_BODY_SIZE_LIMIT.toLong()).toInt()
    }
}
