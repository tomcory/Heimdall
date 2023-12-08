package de.tomcory.heimdall.core.datastore

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.Serializer
import com.google.protobuf.InvalidProtocolBufferException
import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeHosts
import de.tomcory.heimdall.Preferences
import java.io.InputStream
import java.io.OutputStream

object PreferencesSerializer : Serializer<Preferences> {
    override val defaultValue: Preferences = Preferences.newBuilder()
        .setVpnActive(false)
        .setVpnLastUpdated(1L)
        .setVpnPersistTransportLayer(true)
        .setVpnDnsServer("1.1.1.1")
        .setVpnBaseAddress("10.120.0.1/32")
        .setVpnRoute("0.0.0.0/0")
        .setVpnUseProxy(false)
        .setVpnProxyAddress("127.0.0.1:9090")
        .setVpnMonitoringScope(MonitoringScopeApps.APPS_ALL)
        .addAllVpnWhitelistApps(listOf<String>())
        .addAllVpnBlacklistApps(listOf("de.tomcory.heimdall"))

        .setMitmEnable(true)
        .setMitmAppLayerPassthrough(true)
        .setMitmCaCertPath("")
        .setMitmMonitoringScopeApps(MonitoringScopeApps.APPS_ALL)
        .setMitmMonitoringScopeHosts(MonitoringScopeHosts.HOSTS_ALL)
        .addAllMitmWhitelistApps(listOf<String>())
        .addAllMitmBlacklistApps(listOf<String>())
        .addAllMitmWhitelistHosts(listOf<String>())
        .addAllMitmBlacklistHosts(listOf<String>())

        .setLibraryActive(true)
        .setLibraryOnInstall(true)
        .setLibraryLastUpdated(1L)
        .setLibraryMonitoringScope(MonitoringScopeApps.APPS_ALL)
        .addAllLibraryWhitelist(listOf<String>())
        .addAllLibraryBlacklist(listOf<String>())
        .setLibraryPrepopulate(true)

        .setPermissionActive(true)
        .setPermissionOnInstall(true)
        .setPermissionLastUpdated(1L)
        .setPermissionMonitoringScope(MonitoringScopeApps.APPS_ALL)
        .addAllPermissionWhitelist(listOf<String>())
        .addAllPermissionBlacklist(listOf<String>())

        .setCertAlias("heimdallmitm")
        .setCertPassword("changeit")
        .setCertIssuerCn("Heimdall")
        .setCertIssuerO("TU Berlin")
        .setCertIssuerOu("SNET")
        .setCertSubjectCn("Heimdall")
        .setCertSubjectO("HeimdallCert")
        .setCertSubjectOu("HeimdallCertUnit")

        .setProxyActive(false)

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