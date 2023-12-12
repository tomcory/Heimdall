package de.tomcory.heimdall.ui.scanner.traffic

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.ui.scanner.ScannerCard

@Composable
fun TrafficScannerCard(
    modifier: Modifier = Modifier,
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    val scanActive by viewModel.scanActive.collectAsState(initial = viewModel.scanActiveInitial)
    val scanSetup by viewModel.scanSetup.collectAsState(initial = viewModel.scanSetupInitial)
    val lastUpdated by viewModel.lastUpdated.collectAsState(initial = viewModel.lastUpdatedInitial)

    val context = LocalContext.current

    val startForResult = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        viewModel.onVpnPermissionResult(result.resultCode, onShowSnackbar)
    }

    // Handles getting the user's permission to start the VPN service
    LaunchedEffect(Unit) {
        viewModel.vpnPermissionRequestEvent.collect {
            val vpnIntent = VpnService.prepare(context)
            if (vpnIntent != null) {
                // Launch VPN permission request dialog
                startForResult.launch(vpnIntent)
            } else {
                // Handle already granted permission
                viewModel.onVpnPermissionResult(Activity.RESULT_OK, onShowSnackbar)
            }
        }
    }

    ScannerCard(
        title = "Network traffic",
        modifier = modifier,
        lastUpdated = lastUpdated,
        scanStartLabel = "Enable",
        scanStopLabel = "Disable",
        scanActive = scanActive,
        scanSetup = scanSetup,
        onScan = { viewModel.onScan(onShowSnackbar) },
        onScanCancel = { viewModel.onScanCancel() },
        onShowDetails = { viewModel.onShowDetails() },
        infoDialogContent = {
            Text(text = "This scanner monitors all network traffic on your device.")
        },
        onShowSnackbar = onShowSnackbar
    ) {
        /*TODO*/
    }
}