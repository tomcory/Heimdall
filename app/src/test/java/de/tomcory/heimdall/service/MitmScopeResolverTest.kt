package de.tomcory.heimdall.service

import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeHosts
import de.tomcory.heimdall.core.vpn.mitm.MitmScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tests for docs/vpn-mitm-audit.md PKT-24. */
class MitmScopeResolverTest {

    private val system = setOf("com.android.system", "com.android.phone")
    private val whitelist = listOf("com.white.app")
    private val blacklist = listOf("com.black.app")

    private var systemQueried = false

    private fun resolveApps(scope: MonitoringScopeApps) = MitmScopeResolver.resolve(
        appScope = scope,
        whitelistApps = whitelist,
        blacklistApps = blacklist,
        hostScope = MonitoringScopeHosts.HOSTS_ALL,
        whitelistHosts = emptyList(),
        blacklistHosts = emptyList(),
        systemPackages = { systemQueried = true; system }
    )

    private fun resolveHosts(scope: MonitoringScopeHosts) = MitmScopeResolver.resolve(
        appScope = MonitoringScopeApps.APPS_ALL,
        whitelistApps = emptyList(),
        blacklistApps = emptyList(),
        hostScope = scope,
        whitelistHosts = listOf("white.com"),
        blacklistHosts = listOf("black.com"),
        systemPackages = { system }
    )

    @Test
    fun `APPS_ALL intercepts every app without querying system packages`() {
        val scope = resolveApps(MonitoringScopeApps.APPS_ALL)
        assertNull(scope.includedApps)
        assertTrue(scope.excludedApps.isEmpty())
        assertFalse(systemQueried)
    }

    @Test
    fun `APPS_NON_SYSTEM excludes system packages`() {
        val scope = resolveApps(MonitoringScopeApps.APPS_NON_SYSTEM)
        assertNull(scope.includedApps)
        assertEquals(system, scope.excludedApps)
    }

    @Test
    fun `APPS_NON_SYSTEM_BLACKLIST excludes system packages and the blacklist`() {
        val scope = resolveApps(MonitoringScopeApps.APPS_NON_SYSTEM_BLACKLIST)
        assertNull(scope.includedApps)
        assertEquals(system + blacklist, scope.excludedApps)
    }

    @Test
    fun `APPS_WHITELIST includes only the whitelist`() {
        val scope = resolveApps(MonitoringScopeApps.APPS_WHITELIST)
        assertEquals(whitelist.toSet(), scope.includedApps)
        assertTrue(scope.excludedApps.isEmpty())
        assertFalse(systemQueried)
    }

    @Test
    fun `APPS_BLACKLIST excludes only the blacklist`() {
        val scope = resolveApps(MonitoringScopeApps.APPS_BLACKLIST)
        assertNull(scope.includedApps)
        assertEquals(blacklist.toSet(), scope.excludedApps)
        assertFalse(systemQueried)
    }

    @Test
    fun `unrecognised app scope falls back to intercepting everything`() {
        val scope = resolveApps(MonitoringScopeApps.UNRECOGNIZED)
        assertNull(scope.includedApps)
        assertTrue(scope.excludedApps.isEmpty())
    }

    @Test
    fun `host scopes map to the matching host mode and list`() {
        assertEquals(MitmScope.HostMode.ALL, resolveHosts(MonitoringScopeHosts.HOSTS_ALL).hostMode)
        assertTrue(resolveHosts(MonitoringScopeHosts.HOSTS_ALL).hosts.isEmpty())

        val white = resolveHosts(MonitoringScopeHosts.HOSTS_WHITELIST)
        assertEquals(MitmScope.HostMode.WHITELIST, white.hostMode)
        assertEquals(listOf("white.com"), white.hosts)

        val black = resolveHosts(MonitoringScopeHosts.HOSTS_BLACKLIST)
        assertEquals(MitmScope.HostMode.BLACKLIST, black.hostMode)
        assertEquals(listOf("black.com"), black.hosts)

        assertEquals(MitmScope.HostMode.ALL, resolveHosts(MonitoringScopeHosts.UNRECOGNIZED).hostMode)
    }
}
