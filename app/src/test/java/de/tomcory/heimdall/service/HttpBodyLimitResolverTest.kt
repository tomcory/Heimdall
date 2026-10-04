package de.tomcory.heimdall.service

import de.tomcory.heimdall.core.vpn.connection.appLayer.HttpConnection
import org.junit.Assert.assertEquals
import org.junit.Test

/** Tests for docs/vpn-mitm-audit.md PKT-59. */
class HttpBodyLimitResolverTest {

    @Test
    fun `the preference is in KB`() {
        assertEquals(64 * 1024, HttpBodyLimitResolver.resolve(64))
    }

    @Test
    fun `0, the value of installs from before the preference, means the default`() {
        assertEquals(HttpConnection.DEFAULT_MAX_BODY_SIZE, HttpBodyLimitResolver.resolve(0))
        assertEquals(HttpConnection.DEFAULT_MAX_BODY_SIZE, HttpBodyLimitResolver.resolve(-5))
    }

    @Test
    fun `the limit is capped so that a row still fits a CursorWindow`() {
        assertEquals(HttpConnection.MAX_BODY_SIZE_LIMIT, HttpBodyLimitResolver.resolve(4096))
        assertEquals(HttpConnection.MAX_BODY_SIZE_LIMIT, HttpBodyLimitResolver.resolve(Int.MAX_VALUE))
    }
}
