package de.tomcory.heimdall.service

import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.service.VpnAppScopeResolver.AppScope
import de.tomcory.heimdall.service.VpnAppScopeResolver.CHROME_PACKAGE
import de.tomcory.heimdall.service.VpnAppScopeResolver.HEIMDALL_PACKAGE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Which apps the VPN routes: the stored monitoring scope and a session's own apps. */
class VpnAppScopeResolverTest {

    private val system = setOf("com.android.settings", "com.android.phone")

    private fun resolve(
        scope: MonitoringScopeApps,
        whitelist: List<String> = emptyList(),
        blacklist: List<String> = emptyList(),
        doMitm: Boolean = false,
        sessionApps: List<String> = emptyList()
    ) = VpnAppScopeResolver.resolve(scope, whitelist, blacklist, doMitm, sessionApps) { system }

    @Test
    fun `all apps excludes only Heimdall`() {
        assertEquals(AppScope(disallowed = listOf(HEIMDALL_PACKAGE)), resolve(MonitoringScopeApps.APPS_ALL))
    }

    @Test
    fun `with MitM Chrome is excluded as well, once`() {
        assertEquals(listOf(HEIMDALL_PACKAGE, CHROME_PACKAGE), resolve(MonitoringScopeApps.APPS_ALL, doMitm = true).disallowed)
        val blacklisted = resolve(MonitoringScopeApps.APPS_BLACKLIST, blacklist = listOf(CHROME_PACKAGE), doMitm = true)
        assertEquals(listOf(CHROME_PACKAGE, HEIMDALL_PACKAGE), blacklisted.disallowed)
    }

    @Test
    fun `non-system and blacklist scopes add up`() {
        val scope = resolve(MonitoringScopeApps.APPS_NON_SYSTEM_BLACKLIST, blacklist = listOf("com.bank.app", HEIMDALL_PACKAGE))
        assertEquals(system.toList() + listOf("com.bank.app", HEIMDALL_PACKAGE), scope.disallowed)
        assertTrue(scope.allowed.isEmpty())
        assertEquals(system.toList() + HEIMDALL_PACKAGE, resolve(MonitoringScopeApps.APPS_NON_SYSTEM, blacklist = listOf("com.bank.app")).disallowed)
    }

    @Test
    fun `a whitelist allows its apps and disallows nothing`() {
        val scope = resolve(MonitoringScopeApps.APPS_WHITELIST, whitelist = listOf("com.example.app", HEIMDALL_PACKAGE), doMitm = true)
        assertEquals(AppScope(allowed = listOf("com.example.app")), scope)
    }

    @Test
    fun `a session's apps replace the stored scope`() {
        val scope = resolve(
            MonitoringScopeApps.APPS_NON_SYSTEM_BLACKLIST, blacklist = listOf("com.example.app"), doMitm = true,
            sessionApps = listOf("com.example.app", HEIMDALL_PACKAGE, "com.example.app")
        )
        assertEquals(AppScope(allowed = listOf("com.example.app")), scope)
    }
}
