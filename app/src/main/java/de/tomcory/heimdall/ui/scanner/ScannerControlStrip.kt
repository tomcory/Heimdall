package de.tomcory.heimdall.ui.scanner

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.R
import de.tomcory.heimdall.ui.scanner.library.LibraryScannerViewModel
import de.tomcory.heimdall.ui.scanner.permission.PermissionScannerViewModel
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerViewModel
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerViewModel.VpnMode
import de.tomcory.heimdall.ui.theme.MonoFont
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

@Composable
fun ScannerControlStrip(
    onShowSnackbar: (String) -> Unit,
    onShowPreferences: () -> Unit = {},
    trafficVm: TrafficScannerViewModel = hiltViewModel(),
    libraryVm: LibraryScannerViewModel = hiltViewModel(),
    permissionVm: PermissionScannerViewModel = hiltViewModel(),
) {
    val context = LocalContext.current

    // VPN permission launcher
    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        trafficVm.onVpnPermissionResult(result.resultCode, onShowSnackbar)
    }

    LaunchedEffect(Unit) {
        trafficVm.vpnPermissionRequestEvent.collect {
            val vpnIntent = VpnService.prepare(context)
            if (vpnIntent != null) vpnPermissionLauncher.launch(vpnIntent)
            else trafficVm.onVpnPermissionResult(Activity.RESULT_OK, onShowSnackbar)
        }
    }

    val scanActive by trafficVm.scanActive.collectAsState()
    val scanSetup by trafficVm.scanSetup.collectAsState()
    val lastUpdated by trafficVm.lastUpdated.collectAsState(initial = 0L)
    val vpnMode by trafficVm.vpnMode.collectAsState()

    val libScanActive by libraryVm.scanActive.collectAsState()
    val libScanProgress by libraryVm.scanProgress.collectAsState()
    val libLastUpdated by libraryVm.lastUpdated.collectAsState(initial = 0L)

    val permScanActive by permissionVm.scanActive.collectAsState()
    val permScanProgress by permissionVm.scanProgress.collectAsState()
    val permLastUpdated by permissionVm.lastUpdated.collectAsState(initial = 0L)

    Column(modifier = Modifier.fillMaxWidth()) {
        // ── VPN row ────────────────────────────────────────────────────────────
        VpnControlRow(
            scanActive = scanActive,
            scanSetup = scanSetup,
            lastUpdated = lastUpdated,
            vpnMode = vpnMode,
            onVpnModeChanged = { trafficVm.onVpnModeChanged(it, onShowSnackbar) },
            onShowPreferences = onShowPreferences,
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)

        // ── Permission row ─────────────────────────────────────────────────────
        ScannerControlRow(
            label = "Permissions",
            scanActive = permScanActive,
            scanProgress = permScanProgress,
            lastUpdated = permLastUpdated,
            onScan = { permissionVm.onScan(onShowSnackbar) },
            onCancel = { permissionVm.onScanCancel() },
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)

        // ── Library row ────────────────────────────────────────────────────────
        ScannerControlRow(
            label = "Libraries",
            scanActive = libScanActive,
            scanProgress = libScanProgress,
            lastUpdated = libLastUpdated,
            onScan = { libraryVm.onScan(onShowSnackbar) },
            onCancel = { libraryVm.onScanCancel() },
        )
    }
}

// ── VPN row ────────────────────────────────────────────────────────────────────

@Composable
private fun VpnControlRow(
    scanActive: Boolean,
    scanSetup: Boolean,
    lastUpdated: Long,
    vpnMode: VpnMode,
    onVpnModeChanged: (VpnMode) -> Unit,
    onShowPreferences: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            // Label + status
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Traffic",
                    style = MaterialTheme.typography.titleSmall,
                )
                AnimatedContent(
                    targetState = Triple(scanSetup, scanActive, vpnMode),
                    transitionSpec = { fadeIn() togetherWith fadeOut() },
                    label = "vpn-status",
                ) { (isSetup, isActive, _) ->
                    when {
                        isSetup -> Text(
                            text = if (isActive) "Stopping…" else "Starting…",
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = MonoFont,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            ),
                        )
                        isActive -> ElapsedTimer(startTimestamp = lastUpdated)
                        else -> Text(
                            text = if (lastUpdated > 0) "Last: ${relativeTimestamp(lastUpdated)}"
                                   else "Never run",
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = MonoFont,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            ),
                        )
                    }
                }
            }

            if (scanSetup) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                )
            }

            // Settings — only tappable when idle to avoid mid-session config changes
            IconButton(
                onClick = onShowPreferences,
                enabled = !scanActive && !scanSetup,
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_settings),
                    contentDescription = "Scanner preferences",
                    tint = if (!scanActive && !scanSetup)
                        MaterialTheme.colorScheme.onSurfaceVariant
                    else
                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f),
                    modifier = Modifier.size(20.dp),
                )
            }
        }

        // Mode selector — the single control for the VPN's running state
        Spacer(modifier = Modifier.height(8.dp))
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            val options = listOf(
                VpnMode.OFF       to "Off",
                VpnMode.PLAIN_VPN to "Plain VPN",
                VpnMode.MITM_VPN  to "MitM VPN",
            )
            options.forEachIndexed { index, (mode, label) ->
                SegmentedButton(
                    selected = mode == vpnMode,
                    onClick = { onVpnModeChanged(mode) },
                    enabled = !scanSetup,
                    shape = SegmentedButtonDefaults.itemShape(index, options.size),
                ) { Text(label, style = MaterialTheme.typography.labelMedium) }
            }
        }
    }
}

// ── Generic scanner row ────────────────────────────────────────────────────────

@Composable
private fun ScannerControlRow(
    label: String,
    scanActive: Boolean,
    scanProgress: Float,
    lastUpdated: Long,
    onScan: () -> Unit,
    onCancel: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = label, style = MaterialTheme.typography.titleSmall)
            if (scanActive) {
                Spacer(modifier = Modifier.height(4.dp))
                LinearProgressIndicator(
                    progress = { scanProgress },
                    modifier = Modifier.fillMaxWidth(0.85f),
                )
            } else {
                Text(
                    text = if (lastUpdated > 0) "Last: ${relativeTimestamp(lastUpdated)}"
                           else "Never scanned",
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = MonoFont,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    ),
                )
            }
        }

        Spacer(modifier = Modifier.width(8.dp))

        FilledTonalButton(
            onClick = if (scanActive) onCancel else onScan,
            enabled = true,
        ) {
            Text(
                text = if (scanActive) "Cancel" else "Scan",
                style = MaterialTheme.typography.labelMedium,
            )
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

@Composable
private fun ElapsedTimer(startTimestamp: Long) {
    var elapsedMs by remember { mutableStateOf(0L) }
    LaunchedEffect(startTimestamp) {
        while (true) {
            elapsedMs = if (startTimestamp > 0) System.currentTimeMillis() - startTimestamp else 0L
            delay(1_000)
        }
    }
    val h = TimeUnit.MILLISECONDS.toHours(elapsedMs)
    val m = TimeUnit.MILLISECONDS.toMinutes(elapsedMs) % 60
    val s = TimeUnit.MILLISECONDS.toSeconds(elapsedMs) % 60
    Text(
        text = "%02d:%02d:%02d".format(h, m, s),
        style = MaterialTheme.typography.bodySmall.copy(
            fontFamily = MonoFont,
            color = MaterialTheme.colorScheme.primary,
        ),
    )
}

private fun relativeTimestamp(ts: Long): String {
    val diff = System.currentTimeMillis() - ts
    return when {
        diff < 60_000       -> "just now"
        diff < 3_600_000    -> "${diff / 60_000}m ago"
        diff < 86_400_000   -> "${diff / 3_600_000}h ago"
        else -> {
            val cal = Calendar.getInstance().apply { time = Date(ts) }
            val today = Calendar.getInstance()
            val yesterday = Calendar.getInstance().also { it.add(Calendar.DAY_OF_YEAR, -1) }
            when {
                cal.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR) ->
                    "Today " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ts))
                cal.get(Calendar.DAY_OF_YEAR) == yesterday.get(Calendar.DAY_OF_YEAR) ->
                    "Yesterday " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ts))
                else -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(ts))
            }
        }
    }
}
