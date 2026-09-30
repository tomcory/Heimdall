package de.tomcory.heimdall.core.vpn.mitm

import de.tomcory.heimdall.core.vpn.mitm.MitmScope.HostMode
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tests for docs/vpn-mitm-audit.md PKT-24. */
class MitmScopeTest {

    @Test
    fun `ALL intercepts everything`() {
        assertTrue(MitmScope.ALL.shouldIntercept("com.example.app", "example.com"))
        assertTrue(MitmScope.ALL.shouldIntercept(null, "10.0.0.1"))
    }

    @Test
    fun `host whitelist only intercepts matching hosts`() {
        val scope = MitmScope(hostMode = HostMode.WHITELIST, hosts = listOf("example.com"))
        assertTrue(scope.shouldIntercept("com.example.app", "example.com"))
        assertFalse(scope.shouldIntercept("com.example.app", "other.com"))
    }

    @Test
    fun `host blacklist intercepts everything except matching hosts`() {
        val scope = MitmScope(hostMode = HostMode.BLACKLIST, hosts = listOf("example.com"))
        assertFalse(scope.shouldIntercept("com.example.app", "example.com"))
        assertTrue(scope.shouldIntercept("com.example.app", "other.com"))
    }

    @Test
    fun `host entries match subdomains but not lookalike domains`() {
        val scope = MitmScope(hostMode = HostMode.WHITELIST, hosts = listOf("example.com"))
        assertTrue(scope.shouldIntercept(null, "api.example.com"))
        assertTrue(scope.shouldIntercept(null, "a.b.example.com"))
        assertFalse(scope.shouldIntercept(null, "badexample.com"))
        assertFalse(scope.shouldIntercept(null, "example.com.evil.net"))
        assertFalse("a more specific entry must not match its parent", MitmScope(
            hostMode = HostMode.WHITELIST, hosts = listOf("api.example.com")
        ).shouldIntercept(null, "example.com"))
    }

    @Test
    fun `host matching ignores case, a trailing dot and a leading wildcard`() {
        val scope = MitmScope(hostMode = HostMode.WHITELIST, hosts = listOf("*.Example.COM", "tracker.net."))
        assertTrue(scope.shouldIntercept(null, "API.example.com"))
        assertTrue(scope.shouldIntercept(null, "example.com."))
        assertTrue(scope.shouldIntercept(null, "tracker.net"))
    }

    @Test
    fun `empty hostname never matches a host list`() {
        assertFalse(MitmScope(hostMode = HostMode.WHITELIST, hosts = listOf("example.com")).shouldIntercept(null, ""))
        assertTrue(MitmScope(hostMode = HostMode.BLACKLIST, hosts = listOf("example.com")).shouldIntercept(null, ""))
    }

    @Test
    fun `included apps restricts interception to those packages`() {
        val scope = MitmScope(includedApps = setOf("com.example.app"))
        assertTrue(scope.shouldIntercept("com.example.app", "example.com"))
        assertFalse(scope.shouldIntercept("com.other.app", "example.com"))
    }

    @Test
    fun `excluded apps are never intercepted`() {
        val scope = MitmScope(excludedApps = setOf("com.bank.app"))
        assertFalse(scope.shouldIntercept("com.bank.app", "example.com"))
        assertTrue(scope.shouldIntercept("com.example.app", "example.com"))
    }

    @Test
    fun `unknown app is excluded only when an include list is set`() {
        assertFalse(MitmScope(includedApps = setOf("com.example.app")).shouldIntercept(null, "example.com"))
        assertTrue(MitmScope(excludedApps = setOf("com.bank.app")).shouldIntercept(null, "example.com"))
    }

    @Test
    fun `app and host rules must both allow interception`() {
        val scope = MitmScope(
            includedApps = setOf("com.example.app"),
            hostMode = HostMode.BLACKLIST,
            hosts = listOf("bank.com")
        )
        assertTrue(scope.shouldIntercept("com.example.app", "example.com"))
        assertFalse(scope.shouldIntercept("com.example.app", "bank.com"))
        assertFalse(scope.shouldIntercept("com.other.app", "example.com"))
    }
}
