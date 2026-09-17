package de.tomcory.heimdall.ui.scanner

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.ui.scanner.library.LibraryScannerViewModel
import de.tomcory.heimdall.ui.scanner.permission.PermissionScannerViewModel
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerViewModel
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import kotlinx.coroutines.launch

@Composable
fun ScannerScreen(
    scannerVm: ScannerViewModel = hiltViewModel(),
    trafficVm: TrafficScannerViewModel = hiltViewModel(),
    libraryVm: LibraryScannerViewModel = hiltViewModel(),
    permissionVm: PermissionScannerViewModel = hiltViewModel(),
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val showSnackbar: (String) -> Unit = { msg -> scope.launch { snackbarHostState.showSnackbar(msg) } }

    val showPreferencesDialog by scannerVm.showPreferencesDialog.collectAsState()

    val scanActive by trafficVm.scanActive.collectAsState()
    val liveConnections by trafficVm.liveConnections.collectAsState()
    val lastSessionStats by trafficVm.lastSessionStats.collectAsState()
    val permLastUpdated by permissionVm.lastUpdated.collectAsState(initial = 0L)
    val libLastUpdated by libraryVm.lastUpdated.collectAsState(initial = 0L)

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.surface,
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize()) {
            // ── Persistent control strip ───────────────────────────────────────
            ScannerControlStrip(
                onShowSnackbar = showSnackbar,
                onShowPreferences = { scannerVm.onShowPreferencesDialog() },
                trafficVm = trafficVm,
                libraryVm = libraryVm,
                permissionVm = permissionVm,
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))

            // ── Animated dashboard ─────────────────────────────────────────────
            AnimatedContent(
                targetState = scanActive,
                transitionSpec = {
                    (fadeIn() + slideInVertically { it / 10 }) togetherWith
                    (fadeOut() + slideOutVertically { -it / 10 })
                },
                label = "scanner-dashboard-state",
                modifier = Modifier.fillMaxSize(),
            ) { isActive ->
                if (isActive) {
                    LiveDashboard(connections = liveConnections)
                } else {
                    IdleStateDashboard(
                        lastSessionStats = lastSessionStats,
                        permLastUpdated = permLastUpdated,
                        libLastUpdated = libLastUpdated,
                        onScanPermissions = { permissionVm.onScan(showSnackbar) },
                        onScanLibraries = { libraryVm.onScan(showSnackbar) },
                    )
                }
            }
        }

        if (showPreferencesDialog) {
            ScannerPreferencesDialog(onDismiss = { scannerVm.onDismissPreferencesDialog() })
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun ScannerScreenPreview() {
    HeimdallTheme { ScannerScreen() }
}
