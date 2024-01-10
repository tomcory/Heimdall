package de.tomcory.heimdall.ui.scanner.permission

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerViewModel
import de.tomcory.heimdall.ui.settings.BooleanPreference
import de.tomcory.heimdall.ui.settings.CategoryHeadline
import de.tomcory.heimdall.ui.settings.MonitoringScopePreference

@Composable
fun PermissionScannerPreferences(
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    Column {

        CategoryHeadline(
            text = "Permission scanner preferences"
        )

        MonitoringScopePreference(
            text = "Permission scanner scope",
            dialogText = "Permission scanner scope",
            value = viewModel.preferences.permissionMonitoringScope.collectAsState(initial = viewModel.prefInit.permissionMonitoringScopeInitial).value,
            onValueChange = { value -> viewModel.preferences.setPermissionMonitoringScope(value) }
        )

        BooleanPreference(
            text = "Scan apps on install",
            value = viewModel.preferences.permissionOnInstall.collectAsState(initial = viewModel.prefInit.permissionOnInstallInitial).value,
            onValueChange = { value -> viewModel.preferences.setPermissionOnInstall(value) }
        )
    }
}