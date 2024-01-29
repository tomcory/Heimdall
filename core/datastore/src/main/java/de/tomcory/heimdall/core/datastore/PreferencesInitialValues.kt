package de.tomcory.heimdall.core.datastore

import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeHosts

data class PreferencesInitialValues(
    val vpnActiveInitial: Boolean = false,
    val vpnLastUpdatedInitial: Long = 1L,
    val vpnPersistTransportLayerInitial: Boolean = true,
    val vpnDnsServerInitial: String = "1.1.1.1",
    val vpnBaseAddressInitial: String = "10.120.0.1/32",
    val vpnRouteInitial: String = "0.0.0.0/0",
    val vpnUseProxyInitial: Boolean = false,
    val vpnProxyAddressInitial: String = "127.0.0.1:9090",
    val vpnMonitoringScopeInitial: MonitoringScopeApps = MonitoringScopeApps.APPS_ALL,
    val vpnWhitelistAppsInitial: List<String> = listOf(),
    val vpnBlacklistAppsInitial: List<String> = listOf(),

    val mitmEnableInitial: Boolean = true,
    val mitmAppLayerPassthroughInitial: Boolean = true,
    val mitmCaCertPathInitial: String = "",
    val mitmMonitoringScopeAppsInitial: MonitoringScopeApps = MonitoringScopeApps.APPS_ALL,
    val mitmMonitoringScopeHostsInitial: MonitoringScopeHosts = MonitoringScopeHosts.HOSTS_ALL,
    val mitmWhitelistAppsInitial: List<String> = listOf(),
    val mitmBlacklistAppsInitial: List<String> = listOf(),
    val mitmWhitelistHostsInitial: List<String> = listOf(),
    val mitmBlacklistHostsInitial: List<String> = listOf(),

    val libraryActiveInitial: Boolean = true,
    val libraryOnInstallInitial: Boolean = true,
    val libraryLastUpdatedInitial: Long = 1L,
    val libraryMonitoringScopeInitial: MonitoringScopeApps = MonitoringScopeApps.APPS_ALL,
    val libraryWhitelistInitial: List<String> = listOf(),
    val libraryBlacklistInitial: List<String> = listOf(),
    val libraryPrepopulateInitial: Boolean = true,

    val permissionActiveInitial: Boolean = true,
    val permissionOnInstallInitial: Boolean = true,
    val permissionLastUpdatedInitial: Long = 1L,
    val permissionMonitoringScopeInitial: MonitoringScopeApps = MonitoringScopeApps.APPS_ALL,
    val permissionWhitelistInitial: List<String> = listOf(),
    val permissionBlacklistInitial: List<String> = listOf(),

    val certAliasInitial: String = "heimdallmitm",
    val certPasswordInitial: String = "changeit",
    val certIssuerCnInitial: String = "Heimdall",
    val certIssuerOInitial: String = "TU Berlin",
    val certIssuerOuInitial: String = "SNET",
    val certSubjectCnInitial: String = "Heimdall",

    val proxyActiveInitial: Boolean = false,

    val bootScanServiceInitial: Boolean = true,
    val bootVpnServiceInitial: Boolean = false
)
