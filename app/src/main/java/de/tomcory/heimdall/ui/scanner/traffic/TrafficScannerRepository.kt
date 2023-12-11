package de.tomcory.heimdall.ui.scanner.traffic

import androidx.datastore.core.DataStore
import de.tomcory.heimdall.Preferences
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeHosts
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

class TrafficScannerRepository @Inject constructor(
    private val preferences: PreferencesDataSource,
    private val database: HeimdallDatabase
) {

    val vpnActive: Flow<Boolean> = preferences.vpnActive
    val vpnLastUpdated: Flow<Long> = preferences.vpnLastUpdated
    val vpnPersistTransportLayer: Flow<Boolean> = preferences.vpnPersistTransportLayer
    val vpnDnsServer: Flow<String> = preferences.vpnDnsServer
    val vpnBaseAddress: Flow<String> = preferences.vpnBaseAddress
    val vpnRoute: Flow<String> = preferences.vpnRoute
    val vpnUseProxy: Flow<Boolean> = preferences.vpnUseProxy
    val vpnProxyAddress: Flow<String> = preferences.vpnProxyAddress
    val vpnMonitoringScope: Flow<MonitoringScopeApps> = preferences.vpnMonitoringScope
    val vpnWhitelistApps: Flow<List<String>> = preferences.vpnWhitelistApps
    val vpnBlacklistApps: Flow<List<String>> = preferences.vpnBlacklistApps

    val mitmEnable: Flow<Boolean> = preferences.mitmEnable
    val mitmAppLayerPassthrough: Flow<Boolean> = preferences.mitmAppLayerPassthrough
    val mitmCaCertPath: Flow<String> = preferences.mitmCaCertPath
    val mitmMonitoringScopeApps: Flow<MonitoringScopeApps> = preferences.mitmMonitoringScopeApps
    val mitmMonitoringScopeHosts: Flow<MonitoringScopeHosts> = preferences.mitmMonitoringScopeHosts
    val mitmWhitelistApps: Flow<List<String>> = preferences.mitmWhitelistApps
    val mitmBlacklistApps: Flow<List<String>> = preferences.mitmBlacklistApps
    val mitmWhitelistHosts: Flow<List<String>> = preferences.mitmWhitelistHosts
    val mitmBlacklistHosts: Flow<List<String>> = preferences.mitmBlacklistHosts

    val proxyActive: Flow<Boolean> = preferences.proxyActive

    // update functions
    suspend fun updateVpnActive(vpnActive: Boolean) {
        preferences.setVpnActive(vpnActive)
    }

    suspend fun updateVpnLastUpdated(vpnLastUpdated: Long) {
        preferences.setVpnLastUpdated(vpnLastUpdated)
    }

    suspend fun updateVpnPersistTransportLayer(vpnPersistTransportLayer: Boolean) {
        preferences.setVpnPersistTransportLayer(vpnPersistTransportLayer)
    }

    suspend fun updateVpnDnsServer(vpnDnsServer: String) {
        preferences.setVpnDnsServer(vpnDnsServer)
    }

    suspend fun updateVpnBaseAddress(vpnBaseAddress: String) {
        preferences.setVpnBaseAddress(vpnBaseAddress)
    }

    suspend fun updateVpnRoute(vpnRoute: String) {
        preferences.setVpnRoute(vpnRoute)
    }

    suspend fun updateVpnUseProxy(vpnUseProxy: Boolean) {
        preferences.setVpnUseProxy(vpnUseProxy)
    }

    suspend fun updateVpnProxyAddress(vpnProxyAddress: String) {
        preferences.setVpnProxyAddress(vpnProxyAddress)
    }

    suspend fun updateVpnMonitoringScope(vpnMonitoringScope: MonitoringScopeApps) {
        preferences.setVpnMonitoringScope(vpnMonitoringScope)
    }

    suspend fun updateVpnWhitelistApps(vpnWhitelistApps: List<String>) {
        preferences.setVpnWhitelistApps(vpnWhitelistApps)
    }

    suspend fun updateVpnBlacklistApps(vpnBlacklistApps: List<String>) {
        preferences.setVpnBlacklistApps(vpnBlacklistApps)
    }

    suspend fun updateMitmEnable(mitmEnable: Boolean) {
        preferences.setMitmEnable(mitmEnable)
    }

    suspend fun updateMitmAppLayerPassthrough(mitmAppLayerPassthrough: Boolean) {
        preferences.setMitmAppLayerPassthrough(mitmAppLayerPassthrough)
    }

    suspend fun updateMitmCaCertPath(mitmCaCertPath: String) {
        preferences.setMitmCaCertPath(mitmCaCertPath)
    }

    suspend fun updateMitmMonitoringScopeApps(mitmMonitoringScopeApps: MonitoringScopeApps) {
        preferences.setMitmMonitoringScopeApps(mitmMonitoringScopeApps)
    }

    suspend fun updateMitmMonitoringScopeHosts(mitmMonitoringScopeHosts: MonitoringScopeHosts) {
        preferences.setMitmMonitoringScopeHosts(mitmMonitoringScopeHosts)
    }

    suspend fun updateMitmWhitelistApps(mitmWhitelistApps: List<String>) {
        preferences.setMitmWhitelistApps(mitmWhitelistApps)
    }

    suspend fun updateMitmBlacklistApps(mitmBlacklistApps: List<String>) {
        preferences.setMitmBlacklistApps(mitmBlacklistApps)
    }

    suspend fun updateMitmWhitelistHosts(mitmWhitelistHosts: List<String>) {
        preferences.setMitmWhitelistHosts(mitmWhitelistHosts)
    }

    suspend fun updateMitmBlacklistHosts(mitmBlacklistHosts: List<String>) {
        preferences.setMitmBlacklistHosts(mitmBlacklistHosts)
    }

    suspend fun updateProxyActive(proxyActive: Boolean) {
        preferences.setProxyActive(proxyActive)
    }
}