package de.tomcory.heimdall.service

import de.tomcory.heimdall.service.CaptureSessionOptions.InvalidOptionException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** The extras of an adb capture command. */
class CaptureSessionOptionsTest {

    private fun parse(
        tag: String? = null, apps: String? = null, blockHosts: String? = null, mitm: Boolean? = null, quicPolicy: String? = null
    ) = CaptureSessionOptions.parse(tag, apps, blockHosts, mitm, quicPolicy)

    @Test
    fun `no extras leave the preferences in charge`() {
        assertEquals(CaptureSessionOptions.NONE, parse())
        assertEquals(CaptureSessionOptions.NONE, parse(tag = " ", apps = "", blockHosts = " , ", quicPolicy = ""))
    }

    @Test
    fun `lists are split on commas, trimmed and deduplicated`() {
        val options = parse(apps = "com.example.app, org.example.other ,com.example.app", blockHosts = "Ads.Example.com,*.tracker.net, 10.0.0.1")
        assertEquals(listOf("com.example.app", "org.example.other"), options.apps)
        assertEquals(listOf("ads.example.com", "*.tracker.net", "10.0.0.1"), options.blockHosts)
    }

    @Test
    fun `tag, mitm and quic policy are taken over`() {
        val options = parse(tag = " baseline-1 ", mitm = false, quicPolicy = " BLOCK ")
        assertEquals("baseline-1", options.tag)
        assertEquals(false, options.mitm)
        assertEquals("block", options.quicPolicy)
        assertNull(parse(tag = "x").mitm)
    }

    @Test
    fun `a value that is not what its option takes is refused with its reason`() {
        fun reason(block: () -> Unit) = assertThrows(InvalidOptionException::class.java) { block() }.reason
        assertEquals("invalid_tag", reason { parse(tag = "two words") })
        assertEquals("invalid_tag", reason { parse(tag = "a=b") })
        assertEquals("invalid_tag", reason { parse(tag = "x".repeat(CaptureSessionOptions.MAX_TAG_LENGTH + 1)) })
        assertEquals("invalid_apps", reason { parse(apps = "com.example.app,not a package") })
        assertEquals("invalid_apps", reason { parse(apps = "nodots") })
        assertEquals("invalid_block_hosts", reason { parse(blockHosts = "example.com,http://example.org/") })
        assertEquals("invalid_block_hosts", reason { parse(blockHosts = "exa mple.com") })
        assertEquals("invalid_quic_policy", reason { parse(quicPolicy = "intercept") })
    }
}
