package de.tomcory.heimdall.core.datastore

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.Serializer
import com.google.protobuf.InvalidProtocolBufferException
import de.tomcory.heimdall.Preferences
import java.io.InputStream
import java.io.OutputStream

object PreferencesSerializer : Serializer<Preferences> {
    private val initialValues = PreferencesInitialValues()

    override val defaultValue: Preferences = Preferences.newBuilder()
        .setVpnActive(initialValues.vpnActiveInitial)
        .setVpnLastUpdated(initialValues.vpnLastUpdatedInitial)
        .setVpnPersistTransportLayer(initialValues.vpnPersistTransportLayerInitial)
        .setVpnDnsServer(initialValues.vpnDnsServerInitial)
        .setVpnBaseAddress(initialValues.vpnBaseAddressInitial)
        .setVpnRoute(initialValues.vpnRouteInitial)
        .setVpnUseProxy(initialValues.vpnUseProxyInitial)
        .setVpnProxyAddress(initialValues.vpnProxyAddressInitial)
        .setVpnMonitoringScope(initialValues.vpnMonitoringScopeInitial)
        .addAllVpnWhitelistApps(initialValues.vpnWhitelistAppsInitial)
        .addAllVpnBlacklistApps(initialValues.vpnBlacklistAppsInitial)

        .setMitmEnable(initialValues.mitmEnableInitial)
        .setMitmAppLayerPassthrough(initialValues.mitmAppLayerPassthroughInitial)
        .setMitmCaCertPath(initialValues.mitmCaCertPathInitial)
        .setMitmMonitoringScopeApps(initialValues.mitmMonitoringScopeAppsInitial)
        .setMitmMonitoringScopeHosts(initialValues.mitmMonitoringScopeHostsInitial)
        .addAllMitmWhitelistApps(initialValues.mitmWhitelistAppsInitial)
        .addAllMitmBlacklistApps(initialValues.mitmBlacklistAppsInitial)
        .addAllMitmWhitelistHosts(initialValues.mitmWhitelistHostsInitial)
        .addAllMitmBlacklistHosts(initialValues.mitmBlacklistHostsInitial)

        .setLibraryActive(initialValues.libraryActiveInitial)
        .setLibraryOnInstall(initialValues.libraryOnInstallInitial)
        .setLibraryLastUpdated(initialValues.libraryLastUpdatedInitial)
        .setLibraryMonitoringScope(initialValues.libraryMonitoringScopeInitial)
        .addAllLibraryWhitelist(initialValues.libraryWhitelistInitial)
        .addAllLibraryBlacklist(initialValues.libraryBlacklistInitial)
        .setLibraryPrepopulate(initialValues.libraryPrepopulateInitial)

        .setPermissionActive(initialValues.permissionActiveInitial)
        .setPermissionOnInstall(initialValues.permissionOnInstallInitial)
        .setPermissionLastUpdated(initialValues.permissionLastUpdatedInitial)
        .setPermissionMonitoringScope(initialValues.permissionMonitoringScopeInitial)
        .addAllPermissionWhitelist(initialValues.permissionWhitelistInitial)
        .addAllPermissionBlacklist(initialValues.permissionBlacklistInitial)

        .setCertAlias(initialValues.certAliasInitial)
        .setCertPassword(initialValues.certPasswordInitial)
        .setCertIssuerCn(initialValues.certIssuerCnInitial)
        .setCertIssuerO(initialValues.certIssuerOInitial)
        .setCertIssuerOu(initialValues.certIssuerOuInitial)
        .setCertSubjectCn(initialValues.certSubjectCnInitial)

        .setProxyActive(initialValues.proxyActiveInitial)

        .setBootScanService(initialValues.bootScanServiceInitial)
        .setBootVpnService(initialValues.bootVpnServiceInitial)

        .build()

    override suspend fun readFrom(input: InputStream): Preferences {
        try {
            return Preferences.parseFrom(input)
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("Cannot read proto.", exception)
        }
    }

    override suspend fun writeTo(t: Preferences, output: OutputStream) {
        t.writeTo(output)
    }
}