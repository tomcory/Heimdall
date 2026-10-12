package de.tomcory.heimdall.service

import de.tomcory.heimdall.MonitoringScopeApps

/**
 * Decides which apps' traffic is routed through the VPN, from the stored monitoring scope or, for
 * a session that names its apps, from those. Kept free of Android dependencies so it can be unit
 * tested.
 */
object VpnAppScopeResolver {

    const val HEIMDALL_PACKAGE = "de.tomcory.heimdall"
    const val CHROME_PACKAGE = "com.android.chrome"

    /**
     * A VPN interface takes either a list of allowed apps or a list of disallowed ones, never
     * both. An empty [allowed] with an empty [disallowed] routes every app.
     */
    data class AppScope(val allowed: List<String> = emptyList(), val disallowed: List<String> = emptyList())

    /**
     * @param sessionApps The apps of a session that names them (see [CaptureSessionOptions.apps]);
     * if not empty they replace the stored scope.
     * @param systemPackages Supplies the installed system packages. Only called for the
     * `APPS_NON_SYSTEM*` scopes.
     */
    fun resolve(
        scope: MonitoringScopeApps,
        whitelistApps: List<String>,
        blacklistApps: List<String>,
        doMitm: Boolean,
        sessionApps: List<String>,
        systemPackages: () -> Set<String>
    ): AppScope {
        if (sessionApps.isNotEmpty()) {
            return AppScope(allowed = sessionApps.filter { it != HEIMDALL_PACKAGE }.distinct())
        }
        if (scope == MonitoringScopeApps.APPS_WHITELIST) {
            return AppScope(allowed = whitelistApps.filter { it != HEIMDALL_PACKAGE })
        }

        val disallowed = mutableListOf<String>()
        if (scope == MonitoringScopeApps.APPS_NON_SYSTEM || scope == MonitoringScopeApps.APPS_NON_SYSTEM_BLACKLIST) {
            disallowed.addAll(systemPackages())
        }
        if (scope == MonitoringScopeApps.APPS_BLACKLIST || scope == MonitoringScopeApps.APPS_NON_SYSTEM_BLACKLIST) {
            disallowed.addAll(blacklistApps.filter { it != HEIMDALL_PACKAGE })
        }
        // Heimdall must not monitor itself
        disallowed.add(HEIMDALL_PACKAGE)
        // Chrome doesn't work with MitM
        if (doMitm && CHROME_PACKAGE !in disallowed) {
            disallowed.add(CHROME_PACKAGE)
        }
        return AppScope(disallowed = disallowed)
    }
}
