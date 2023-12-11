package de.tomcory.heimdall.ui.scanner.permission

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import de.tomcory.heimdall.ui.scanner.ScannerCard

@Composable
fun PermissionScannerCard(
    modifier: Modifier = Modifier,
    viewModel: PermissionScannerViewModel = viewModel(),
    onShowSnackbar: (String) -> Unit
) {
    val scanActive by viewModel.scanActive.collectAsState(initial = viewModel.scanActiveInitial)
    val scanProgress by viewModel.scanProgress.collectAsState(initial = viewModel.scanProgressInitial)
    val lastUpdated by viewModel.lastUpdated.collectAsState(initial = viewModel.lastUpdatedInitial)

    ScannerCard(
        title = "App permissions",
        lastUpdated = lastUpdated,
        scanActive = scanActive,
        scanProgress = { scanProgress },
        onScan = { viewModel.onScan(onShowSnackbar) },
        onScanCancel = { viewModel.onScanCancel() },
        onShowSettings = { viewModel.onShowSettings() },
        onShowDetails = { viewModel.onShowDetails() },
        onShowSnackbar = onShowSnackbar
    ) {
        // TODO: Implement UI
    }
}