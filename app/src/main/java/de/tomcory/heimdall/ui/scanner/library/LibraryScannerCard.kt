package de.tomcory.heimdall.ui.scanner.library

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import de.tomcory.heimdall.ui.scanner.ScannerCard
import androidx.lifecycle.viewmodel.compose.viewModel

@Composable
fun LibraryScannerCard(
    modifier: Modifier = Modifier,
    viewModel: LibraryScannerViewModel = viewModel(),
    onShowSnackbar: (String) -> Unit
) {
    val scanActive by viewModel.scanActive.collectAsState(initial = viewModel.scanActiveInitial)
    val scanProgress by viewModel.scanProgress.collectAsState(initial = viewModel.scanProgressInitial)
    val lastUpdated by viewModel.lastUpdated.collectAsState(initial = viewModel.lastUpdatedInitial)

    ScannerCard(
        title = "Third-party libraries",
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