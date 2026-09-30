package de.tomcory.heimdall.service

import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeHosts
import de.tomcory.heimdall.core.vpn.mitm.MitmScope

/**
 * Turns the user's MitM monitoring-scope preferences into the [MitmScope] the VPN applies
 * (docs/vpn-mitm-audit.md PKT-24). Kept free of Android dependencies so it can be unit tested.
 */
object MitmScopeResolver {

    /**
     * @param systemPackages Supplies the installed system packages. Only called for the
     * `APPS_NON_SYSTEM*` scopes, so the package manager isn't queried unless needed.
     */
    fun resolve(
        appScope: MonitoringScopeApps,
        whitelistApps: List<String>,
        blacklistApps: List<String>,
        hostScope: MonitoringScopeHosts,
        whitelistHosts: List<String>,
        blacklistHosts: List<String>,
        systemPackages: () -> Set<String>
    ): MitmScope {
        val includedApps: Set<String>? = if (appScope == MonitoringScopeApps.APPS_WHITELIST) whitelistApps.toSet() else null
        val excludedApps: Set<String> = when (appScope) {
            MonitoringScopeApps.APPS_NON_SYSTEM -> systemPackages()
            MonitoringScopeApps.APPS_NON_SYSTEM_BLACKLIST -> systemPackages() + blacklistApps
            MonitoringScopeApps.APPS_BLACKLIST -> blacklistApps.toSet()
            else -> emptySet()
        }
        val (hostMode, hosts) = when (hostScope) {
            MonitoringScopeHosts.HOSTS_WHITELIST -> MitmScope.HostMode.WHITELIST to whitelistHosts
            MonitoringScopeHosts.HOSTS_BLACKLIST -> MitmScope.HostMode.BLACKLIST to blacklistHosts
            else -> MitmScope.HostMode.ALL to emptyList()
        }
        return MitmScope(includedApps, excludedApps, hostMode, hosts)
    }
}
