package de.tomcory.heimdall.ui.settings

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import de.tomcory.heimdall.application.preferencesStore
import de.tomcory.heimdall.core.datastore.PreferencesSerializer

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PreferencesScreen(onDismissRequest: () -> Unit) {
    /*
        Scanner
            - ScanService toggle
            - PermissionScanner toggle
            - LibraryScanner toggle
            - LibraryScanner autoload trackers
        VPN
            - Monitoring scope (apps)
                - all | no system | whitelist | blacklist
            - Persistence
            - DNS server
            - Base address
            - Route
            - Proxy (requires Android 10+)
                - enable | disable
                - proxy address
        TLS MitM
            - enabled/disabled
            - CA certificate
                - show
                - generate new
                - select existing
            - MitM scope (apps)
                - all | no system | whitelist | blacklist
            - MitM scope (hosts)
                - all | whitelist | blacklist
                - dynamically exclude failed connections
        Database
            - Export
                - database as...
                    - .sqlite
                    - .zip of csv
                - table as...
                    - .sqlite
                    - .csv
                    - .json (tex)
            - Reset contents
            - Delete database
     */
    val snackBarHostState = remember {
        SnackbarHostState()
    }

    Dialog(
        onDismissRequest = onDismissRequest,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = { Text(text = "Settings") },
                    navigationIcon = {
                        IconButton(
                            onClick = onDismissRequest,
                            modifier = Modifier.padding(0.dp, 0.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.ArrowBack,
                                contentDescription = "Close preferences dialog"
                            )
                        }
                    }
                )
            },
            snackbarHost = {
                SnackbarHost(snackBarHostState)
            }
        ) {
            LazyColumn(modifier = Modifier.padding(it)) {

                item {
                    ScannerPreferences()
                }

                item {
                    Divider()
                }

                item {
                    VpnPreferences()
                }

                item {
                    Divider()
                }

                item {
                    MitmPreferences(snackBarHostState)
                }
            }
        }
    }
}

@Composable
fun ScannerPreferences() {
    val dataStore = LocalContext.current.preferencesStore
    val context = LocalContext.current
    val preferences =
        dataStore.data.collectAsStateWithLifecycle(initialValue = PreferencesSerializer.defaultValue)

    /*Column {
        CategoryHeadline(text = "Scanner preferences")

        BooleanPreference(
            text = "Scan apps on installation",
            value = preferences.value.scanEnable,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setScanEnable(value).build()
                }
            }
        )

        ActionPreference(text = "Scan apps now", hasProgress = true) {
            ScanManager.create(context).scanAllApps(context, it)
        }

        BooleanPreference(
            text = "Enable PermissionScanner",
            value = preferences.value.scanPermissionScannerEnable,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setScanPermissionScannerEnable(value).build()
                }
            }
        )

        BooleanPreference(
            text = "Enable LibraryScanner",
            value = preferences.value.scanLibraryScannerEnable,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setScanLibraryScannerEnable(value).build()
                }
            }
        )

        BooleanPreference(
            text = "Automatically load Exodus trackers",
            value = preferences.value.scanLibraryScannerPrepopulate,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setScanLibraryScannerEnable(value).build()
                }
            }
        )

        MonitoringScopePreference(
            text = "ScanManager monitoring scope",
            dialogText = "ScanService monitoring scope",
            value = preferences.value.scanMonitoringScope,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setScanMonitoringScope(value).build()
                }
            }
        )

        BlackWhitelistPreference(
            text = "Configure ScanManager white-/blacklist",
            whitelistSource = { preferences.value.scanWhitelistedAppsList },
            blacklistSource = { preferences.value.scanBlacklistedAppsList },
            onSave = { newWhitelist, newBlacklist ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().clearVpnWhitelistedApps()
                        .addAllScanWhitelistedApps(newWhitelist).build()
                }
                dataStore.updateData { preferences ->
                    preferences.toBuilder().clearVpnBlacklistedApps()
                        .addAllScanBlacklistedApps(newBlacklist).build()
                }
            }
        )
    }*/
}

@Composable
fun VpnPreferences() {
    val dataStore = LocalContext.current.preferencesStore
    val preferences =
        dataStore.data.collectAsStateWithLifecycle(initialValue = PreferencesSerializer.defaultValue)

    /*Column {

        CategoryHeadline(text = "VPN preferences")

        MonitoringScopePreference(
            text = "VPN monitoring scope",
            dialogText = "VPN monitoring scope",
            value = preferences.value.vpnMonitoringScope,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setVpnMonitoringScope(value).build()
                }
            }
        )

        BlackWhitelistPreference(
            text = "Configure VPN white-/blacklist",
            whitelistSource = { preferences.value.vpnWhitelistedAppsList },
            blacklistSource = { preferences.value.vpnBlacklistedAppsList },
            onSave = { newWhitelist, newBlacklist ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().clearVpnWhitelistedApps()
                        .addAllVpnWhitelistedApps(newWhitelist).build()
                }
                dataStore.updateData { preferences ->
                    preferences.toBuilder().clearVpnBlacklistedApps()
                        .addAllVpnBlacklistedApps(newBlacklist).build()
                }
            }
        )

        BooleanPreference(
            text = "Persist transport-layer packets",
            value = preferences.value.vpnPersistTransportLayer,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setVpnPersistTransportLayer(value).build()
                }
            }
        )

        StringPreference(
            text = "VPN base address",
            dialogText = "VPN base address",
            value = preferences.value.vpnBaseAddress,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setVpnBaseAddress(value).build()
                }
            }
        )

        StringPreference(
            text = "VPN capture route",
            dialogText = "VPN capture route",
            value = preferences.value.vpnBaseAddress,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setVpnRoute(value).build()
                }
            }
        )

        BooleanPreference(
            text = "Use proxy",
            value = preferences.value.vpnUseProxy,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setVpnUseProxy(value).build()
                }
            }
        )

        StringPreference(
            text = "Proxy address",
            dialogText = "Proxy address",
            value = preferences.value.vpnProxyAddress,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setVpnProxyAddress(value).build()
                }
            }
        )
    }*/
}

@Composable
fun MitmPreferences(snackBarHostState: SnackbarHostState) {
    val dataStore = LocalContext.current.preferencesStore
    val preferences = dataStore.data.collectAsState(initial = PreferencesSerializer.defaultValue)

    /*Column {

        CategoryHeadline(text = "MitM-VPN preferences")

        BooleanPreference(
            text = "Enable MitM-VPN",
            value = preferences.value.mitmEnable,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setMitmEnable(value).build()
                }
            }
        )

        MagiskExportPreference(snackBarHostState)

        MonitoringScopePreference(
            text = "MitM-VPN monitoring scope",
            dialogText = "MitM-VPN monitoring scope",
            value = preferences.value.mitmMonitoringScope,
            onValueChange = { value ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().setMitmMonitoringScope(value).build()
                }
            }
        )

        BlackWhitelistPreference(
            text = "Configure MitM-VPN white-/blacklist",
            whitelistSource = { preferences.value.mitmWhitelistedAppsList },
            blacklistSource = { preferences.value.mitmBlacklistedAppsList },
            onSave = { newWhitelist, newBlacklist ->
                dataStore.updateData { preferences ->
                    preferences.toBuilder().clearVpnWhitelistedApps()
                        .addAllVpnWhitelistedApps(newWhitelist).build()
                }
                dataStore.updateData { preferences ->
                    preferences.toBuilder().clearVpnBlacklistedApps()
                        .addAllVpnBlacklistedApps(newBlacklist).build()
                }
            }
        )
    }*/
}

@Preview
@Composable
fun VpnPreferencesPreview() {
    VpnPreferences()
}

@Preview
@Composable
fun MitmPreferencesPreview() {
    MitmPreferences(SnackbarHostState())
}

@Preview
@Composable
fun ScannerPreferencesPreview() {
    ScannerPreferences()
}