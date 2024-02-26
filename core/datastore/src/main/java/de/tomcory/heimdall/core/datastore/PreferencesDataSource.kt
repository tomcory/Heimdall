package de.tomcory.heimdall.core.datastore

import androidx.datastore.core.DataStore
import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeHosts
import de.tomcory.heimdall.Preferences
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

class PreferencesDataSource @Inject constructor(
    private val datastore: DataStore<Preferences>
) {
    // provides the initial values for all fields of Preferences
    val initialValues = PreferencesInitialValues()

    /*
     * Getters for every field of Preferences, returning Flows
     */
    val vpnActive: Flow<Boolean> = datastore.data.map { it.vpnActive }
    val vpnLastUpdated: Flow<Long> = datastore.data.map { it.vpnLastUpdated }
    val vpnPersistTransportLayer: Flow<Boolean> = datastore.data.map { it.vpnPersistTransportLayer }
    val vpnDnsServer: Flow<String> = datastore.data.map { it.vpnDnsServer }
    val vpnBaseAddress: Flow<String> = datastore.data.map { it.vpnBaseAddress }
    val vpnRoute: Flow<String> = datastore.data.map { it.vpnRoute }
    val vpnUseProxy: Flow<Boolean> = datastore.data.map { it.vpnUseProxy }
    val vpnProxyAddress: Flow<String> = datastore.data.map { it.vpnProxyAddress }
    val vpnMonitoringScope: Flow<MonitoringScopeApps> = datastore.data.map { it.vpnMonitoringScope }
    val vpnWhitelistApps: Flow<List<String>> = datastore.data.map { it.vpnWhitelistAppsList }
    val vpnBlacklistApps: Flow<List<String>> = datastore.data.map { it.vpnBlacklistAppsList }

    val mitmEnable: Flow<Boolean> = datastore.data.map { it.mitmEnable }
    val mitmAppLayerPassthrough: Flow<Boolean> = datastore.data.map { it.mitmAppLayerPassthrough }
    val mitmCaCertPath: Flow<String> = datastore.data.map { it.mitmCaCertPath }
    val mitmMonitoringScopeApps: Flow<MonitoringScopeApps> = datastore.data.map { it.mitmMonitoringScopeApps }
    val mitmMonitoringScopeHosts: Flow<MonitoringScopeHosts> = datastore.data.map { it.mitmMonitoringScopeHosts }
    val mitmWhitelistApps: Flow<List<String>> = datastore.data.map { it.mitmWhitelistAppsList }
    val mitmBlacklistApps: Flow<List<String>> = datastore.data.map { it.mitmBlacklistAppsList }
    val mitmWhitelistHosts: Flow<List<String>> = datastore.data.map { it.mitmWhitelistHostsList }
    val mitmBlacklistHosts: Flow<List<String>> = datastore.data.map { it.mitmBlacklistHostsList }

    val libraryActive: Flow<Boolean> = datastore.data.map { it.libraryActive }
    val libraryOnInstall: Flow<Boolean> = datastore.data.map { it.libraryOnInstall }
    val libraryLastUpdated: Flow<Long> = datastore.data.map { it.libraryLastUpdated }
    val libraryMonitoringScope: Flow<MonitoringScopeApps> = datastore.data.map { it.libraryMonitoringScope }
    val libraryWhitelist: Flow<List<String>> = datastore.data.map { it.libraryWhitelistList }
    val libraryBlacklist: Flow<List<String>> = datastore.data.map { it.libraryBlacklistList }
    val libraryPrepopulate: Flow<Boolean> = datastore.data.map { it.libraryPrepopulate }

    val permissionActive: Flow<Boolean> = datastore.data.map { it.permissionActive }
    val permissionOnInstall: Flow<Boolean> = datastore.data.map { it.permissionOnInstall }
    val permissionLastUpdated: Flow<Long> = datastore.data.map { it.permissionLastUpdated }
    val permissionMonitoringScope: Flow<MonitoringScopeApps> = datastore.data.map { it.permissionMonitoringScope }
    val permissionWhitelist: Flow<List<String>> = datastore.data.map { it.permissionWhitelistList }
    val permissionBlacklist: Flow<List<String>> = datastore.data.map { it.permissionBlacklistList }

    val certAlias: Flow<String> = datastore.data.map { it.certAlias }
    val certPassword: Flow<String> = datastore.data.map { it.certPassword }
    val certIssuerCn: Flow<String> = datastore.data.map { it.certIssuerCn }
    val certIssuerO: Flow<String> = datastore.data.map { it.certIssuerO }
    val certIssuerOu: Flow<String> = datastore.data.map { it.certIssuerOu }
    val certSubjectCn: Flow<String> = datastore.data.map { it.certSubjectCn }
    val certSubjectO: Flow<String> = datastore.data.map { it.certSubjectO }
    val certSubjectOu: Flow<String> = datastore.data.map { it.certSubjectOu }

    val proxyActive: Flow<Boolean> = datastore.data.map { it.proxyActive }

    val bootScanService: Flow<Boolean> = datastore.data.map { it.bootScanService }
    val bootVpnService: Flow<Boolean> = datastore.data.map { it.bootVpnService }

    /*
     * Setters for every field of Preferences
     */

    suspend fun setVpnActive(vpnActive: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnActive(vpnActive).build()
        }
    }

    suspend fun setVpnLastUpdated(vpnLastUpdated: Long) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnLastUpdated(vpnLastUpdated).build()
        }
    }

    suspend fun setVpnPersistTransportLayer(vpnPersistTransportLayer: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnPersistTransportLayer(vpnPersistTransportLayer).build()
        }
    }

    suspend fun setVpnDnsServer(vpnDnsServer: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnDnsServer(vpnDnsServer).build()
        }
    }

    suspend fun setVpnBaseAddress(vpnBaseAddress: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnBaseAddress(vpnBaseAddress).build()
        }
    }

    suspend fun setVpnRoute(vpnRoute: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnRoute(vpnRoute).build()
        }
    }

    suspend fun setVpnUseProxy(vpnUseProxy: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnUseProxy(vpnUseProxy).build()
        }
    }

    suspend fun setVpnProxyAddress(vpnProxyAddress: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnProxyAddress(vpnProxyAddress).build()
        }
    }

    suspend fun setVpnMonitoringScope(vpnMonitoringScope: MonitoringScopeApps) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setVpnMonitoringScope(vpnMonitoringScope).build()
        }
    }

    suspend fun setVpnWhitelistApps(vpnWhitelistApps: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearVpnWhitelistApps().addAllVpnWhitelistApps(vpnWhitelistApps).build()
        }
    }

    suspend fun setVpnBlacklistApps(vpnBlacklistApps: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearVpnBlacklistApps().addAllVpnBlacklistApps(vpnBlacklistApps).build()
        }
    }

    suspend fun setMitmEnable(mitmEnable: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setMitmEnable(mitmEnable).build()
        }
    }

    suspend fun setMitmAppLayerPassthrough(mitmAppLayerPassthrough: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setMitmAppLayerPassthrough(mitmAppLayerPassthrough).build()
        }
    }

    suspend fun setMitmCaCertPath(mitmCaCertPath: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setMitmCaCertPath(mitmCaCertPath).build()
        }
    }

    suspend fun setMitmMonitoringScopeApps(mitmMonitoringScopeApps: MonitoringScopeApps) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setMitmMonitoringScopeApps(mitmMonitoringScopeApps).build()
        }
    }

    suspend fun setMitmMonitoringScopeHosts(mitmMonitoringScopeHosts: MonitoringScopeHosts) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setMitmMonitoringScopeHosts(mitmMonitoringScopeHosts).build()
        }
    }

    suspend fun setMitmWhitelistApps(mitmWhitelistApps: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearMitmWhitelistApps().addAllMitmWhitelistApps(mitmWhitelistApps).build()
        }
    }

    suspend fun setMitmBlacklistApps(mitmBlacklistApps: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearMitmBlacklistApps().addAllMitmBlacklistApps(mitmBlacklistApps).build()
        }
    }

    suspend fun setMitmWhitelistHosts(mitmWhitelistHosts: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearMitmWhitelistHosts().addAllMitmWhitelistHosts(mitmWhitelistHosts).build()
        }
    }

    suspend fun setMitmBlacklistHosts(mitmBlacklistHosts: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearMitmBlacklistHosts().addAllMitmBlacklistHosts(mitmBlacklistHosts).build()
        }
    }

    suspend fun setLibraryActive(libraryActive: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setLibraryActive(libraryActive).build()
        }
    }

    suspend fun setLibraryOnInstall(libraryOnInstall: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setLibraryOnInstall(libraryOnInstall).build()
        }
    }

    suspend fun setLibraryLastUpdated(libraryLastUpdated: Long) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setLibraryLastUpdated(libraryLastUpdated).build()
        }
    }

    suspend fun setLibraryMonitoringScope(libraryMonitoringScope: MonitoringScopeApps) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setLibraryMonitoringScope(libraryMonitoringScope).build()
        }
    }

    suspend fun setLibraryWhitelist(libraryWhitelist: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearLibraryWhitelist().addAllLibraryWhitelist(libraryWhitelist).build()
        }
    }

    suspend fun setLibraryBlacklist(libraryBlacklist: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearLibraryBlacklist().addAllLibraryBlacklist(libraryBlacklist).build()
        }
    }

    suspend fun setLibraryPrepopulate(libraryPrepopulate: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setLibraryPrepopulate(libraryPrepopulate).build()
        }
    }

    suspend fun setPermissionActive(permissionActive: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setPermissionActive(permissionActive).build()
        }
    }

    suspend fun setPermissionOnInstall(permissionOnInstall: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setPermissionOnInstall(permissionOnInstall).build()
        }
    }

    suspend fun setPermissionLastUpdated(permissionLastUpdated: Long) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setPermissionLastUpdated(permissionLastUpdated).build()
        }
    }

    suspend fun setPermissionMonitoringScope(permissionMonitoringScope: MonitoringScopeApps) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setPermissionMonitoringScope(permissionMonitoringScope).build()
        }
    }

    suspend fun setPermissionWhitelist(permissionWhitelist: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearPermissionWhitelist().addAllPermissionWhitelist(permissionWhitelist).build()
        }
    }

    suspend fun setPermissionBlacklist(permissionBlacklist: List<String>) {
        datastore.updateData { preferences ->
            preferences.toBuilder().clearPermissionBlacklist().addAllPermissionBlacklist(permissionBlacklist).build()
        }
    }

    suspend fun setCertAlias(certAlias: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertAlias(certAlias).build()
        }
    }

    suspend fun setCertPassword(certPassword: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertPassword(certPassword).build()
        }
    }

    suspend fun setCertIssuerCn(certIssuerCn: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertIssuerCn(certIssuerCn).build()
        }
    }

    suspend fun setCertIssuerO(certIssuerO: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertIssuerO(certIssuerO).build()
        }
    }

    suspend fun setCertIssuerOu(certIssuerOu: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertIssuerOu(certIssuerOu).build()
        }
    }

    suspend fun setCertSubjectCn(certSubjectCn: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertSubjectCn(certSubjectCn).build()
        }
    }

    suspend fun setCertSubjectO(certSubjectO: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertSubjectO(certSubjectO).build()
        }
    }

    suspend fun setCertSubjectOu(certSubjectOu: String) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setCertSubjectOu(certSubjectOu).build()
        }
    }

    suspend fun setProxyActive(proxyActive: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setProxyActive(proxyActive).build()
        }
    }

    suspend fun setBootScanService(bootScanService: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setBootScanService(bootScanService).build()
        }
    }

    suspend fun setBootVpnService(bootVpnService: Boolean) {
        datastore.updateData { preferences ->
            preferences.toBuilder().setBootVpnService(bootVpnService).build()
        }
    }
}