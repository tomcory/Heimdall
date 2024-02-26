package de.tomcory.heimdall.ui.scanner.library

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerViewModel
import de.tomcory.heimdall.ui.settings.BooleanPreference
import de.tomcory.heimdall.ui.settings.CategoryHeadline
import de.tomcory.heimdall.ui.settings.MonitoringScopePreference

@Composable
fun LibraryScannerPreferences(
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    Column {

        CategoryHeadline(
            text = "Third-party scanner preferences"
        )

        MonitoringScopePreference(
            text = "Third-party scanner scope",
            dialogText = "Third-party scanner scope",
            value = viewModel.preferences.libraryMonitoringScope.collectAsState(initial = viewModel.prefInit.libraryMonitoringScopeInitial).value,
            onValueChange = { value -> viewModel.preferences.setLibraryMonitoringScope(value) }
        )

        BooleanPreference(
            text = "Scan apps on install",
            value = viewModel.preferences.libraryOnInstall.collectAsState(initial = viewModel.prefInit.libraryOnInstallInitial).value,
            onValueChange = { value -> viewModel.preferences.setLibraryOnInstall(value) }
        )
    }
}