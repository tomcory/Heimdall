package de.tomcory.heimdall.ui.scanner.permission

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.ui.scanner.ScannerCard

@Composable
fun PermissionScannerCard(
    modifier: Modifier = Modifier,
    viewModel: PermissionScannerViewModel = hiltViewModel(),
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
        onShowDetails = { viewModel.onShowDetails() },
        infoDialogContent = {
            Text(text = "This scanner monitors all app permissions on your device.")
        },
        onShowSnackbar = onShowSnackbar
    ) {
        // TODO: Implement UI
    }
}