package de.tomcory.heimdall.ui.scanner.traffic

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedIconButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.R
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerViewModel.VpnMode
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * TrafficScannerCard composable function.
 *
 * @param modifier Modifier for the composable.
 * @param viewModel TrafficScannerViewModel instance.
 * @param onShowSnackbar Function to show a snackbar.
 */
@Composable
fun TrafficScannerCard(
    modifier: Modifier = Modifier,
    viewModel: TrafficScannerViewModel = hiltViewModel(),
    onShowSnackbar: (String) -> Unit
) {
    // Collect state from the view model
    val scanActive by viewModel.scanActive.collectAsState(initial = viewModel.scanActiveInitial)
    val scanSetup by viewModel.scanSetup.collectAsState(initial = viewModel.scanSetupInitial)
    val lastUpdated by viewModel.lastUpdated.collectAsState(initial = viewModel.lastUpdatedInitial)
    val vpnMode by viewModel.vpnMode.collectAsState(initial = VpnMode.BASE)

    // Get the current context
    val context = LocalContext.current

    // State to show the info dialog
    var showInfoDialog by remember { mutableStateOf(false) }

    // Launcher for the VPN permission request
    val startForResult =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            viewModel.onVpnPermissionResult(result.resultCode, onShowSnackbar)
        }

    // Handle getting the user's permission to start the VPN service
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

    // Call the TrafficScannerCardContent composable
    TrafficScannerCardContent(
        scanActive = scanActive,
        scanSetup = scanSetup,
        lastUpdated = lastUpdated,
        vpnMode = vpnMode,
        modifier = modifier,
        onStartScan = { viewModel.onScan(onShowSnackbar) },
        onStopScan = { viewModel.onScanCancel() },
        onShowDetails = { viewModel.onShowDetails() },
        onVpnModeChanged = { viewModel.onVpnModeChanged(it) }
    )
}

/**
 * Content of the TrafficScannerCard without ViewModel dependency for previews.
 *
 * @param scanActive Whether the scan is active.
 * @param scanSetup Whether the scan setup is complete.
 * @param lastUpdated Last updated timestamp.
 * @param vpnMode Current VPN mode.
 * @param modifier Modifier for the composable.
 * @param onStartScan Function to start the scan.
 * @param onStopScan Function to stop the scan.
 * @param onShowDetails Function to show details.
 * @param onVpnModeChanged Function to change the VPN mode.
 */

@Composable
fun TrafficScannerCardContent(
    scanActive: Boolean,
    scanSetup: Boolean?,
    lastUpdated: Long,
    vpnMode: VpnMode = VpnMode.BASE,
    modifier: Modifier = Modifier,
    onStartScan: () -> Unit = {},
    onStopScan: () -> Unit = {},
    onShowDetails: () -> Unit = {},
    onVpnModeChanged: (VpnMode) -> Unit = {}
) {
    // State to show the info dialog
    var showInfoDialog by remember { mutableStateOf(false) }

    // Main column
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Column for the MitM mode selection
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Animated content to switch between mode selector and active indicator
            AnimatedContent(
                targetState = scanActive,
                transitionSpec = {
                    fadeIn(animationSpec = tween(300)) togetherWith
                            fadeOut(animationSpec = tween(300))
                },
                contentAlignment = Alignment.Center,
                label = "MitM Mode Section Animation"
            ) { isActive ->
                if (isActive) {
                    // Show mode indicator and timer when active
                    ActiveModeIndicator(vpnMode = vpnMode, lastUpdated = lastUpdated)
                } else {
                    // Show mode selector when inactive
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        // Text for the MitM mode
                        Text(
                            text = "MitM Mode",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        // Spacer
                        Spacer(modifier = Modifier.height(8.dp))

                        // Single choice segmented button row
                        SingleChoiceSegmentedButtonRow(
                            modifier = Modifier.padding(horizontal = 16.dp)
                        ) {
                            // Options for the segmented button row
                            val options = listOf(
                                Pair(VpnMode.BASE, "Off"),
                                Pair(VpnMode.MITM_VPN, "VPN"),
                            )

                            // Iterate over the options
                            options.forEachIndexed { index, (mode, label) ->
                                // Segmented button
                                SegmentedButton(
                                    selected = mode == vpnMode,
                                    onClick = { onVpnModeChanged(mode) },
                                    enabled = !scanActive && scanSetup != true,
                                    shape = SegmentedButtonDefaults.itemShape(
                                        index = index,
                                        count = options.size
                                    )
                                ) {
                                    // Text for the segmented button
                                    Text(label)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Spacer
        Spacer(modifier = Modifier.height(16.dp))

        // Scanner button with export and settings buttons
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Export button
            OutlinedIconButton(
                onClick = { /* Handle export button click */ },
                enabled = !scanActive && scanSetup == false,
                border = ButtonDefaults.outlinedButtonBorder(!scanActive && scanSetup == false),
                modifier = Modifier.size(48.dp)
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_export_24),
                    contentDescription = "Export",
                    modifier = Modifier.size(24.dp),
                    tint = if (!scanActive && scanSetup == false)
                        MaterialTheme.colorScheme.onSurfaceVariant
                    else
                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)
                )
            }

            Spacer(modifier = Modifier.width(43.dp))

            // Scanner button
            ScannerButton(
                scanActive = scanActive,
                scanSetup = scanSetup,
                onStartScan = onStartScan,
                onStopScan = onStopScan
            )

            Spacer(modifier = Modifier.width(43.dp))

            // Settings button
            OutlinedIconButton(
                onClick = { /* Handle settings button click */ },
                enabled = !scanActive && scanSetup == false,
                border = ButtonDefaults.outlinedButtonBorder(!scanActive && scanSetup == false),
                modifier = Modifier.size(48.dp)
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_settings_24),
                    contentDescription = "Settings",
                    modifier = Modifier.size(24.dp),
                    tint = if (!scanActive && scanSetup == false)
                        MaterialTheme.colorScheme.onSurfaceVariant
                    else
                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)
                )
            }
        }
    }

    // Show the info dialog if required
    if (showInfoDialog) {
        AlertDialog(
            onDismissRequest = { showInfoDialog = false },
            title = { Text("Network Traffic Monitor") },
            text = {
                Text(
                    "This scanner monitors all network traffic on your device. " +
                            "It creates a VPN connection that routes traffic through our analyzer " +
                            "to detect potentially suspicious connections.\n\n" +
                            "VPN Modes:\n" +
                            "• Base - Basic traffic monitoring\n" +
                            "• MitM-VPN - Man-in-the-middle inspection using VPN\n" +
                            "• MitM-Proxy - Man-in-the-middle inspection using proxy"
                )
            },
            confirmButton = {
                TextButton(onClick = { showInfoDialog = false }) {
                    Text("Got it")
                }
            }
        )
    }
}

/**
 * Active Mode Indicator composable function that shows the selected mode and a timer.
 *
 * @param vpnMode Current VPN mode.
 * @param lastUpdated The timestamp when the scan was started.
 */
@Composable
fun ActiveModeIndicator(vpnMode: VpnMode, lastUpdated: Long) {
    // State for the timer
    var elapsedTime by remember { mutableStateOf(0L) }

    // Timer effect to update the elapsed time every second
    LaunchedEffect(Unit) {
        while (true) {
            elapsedTime = if (lastUpdated > 0) {
                System.currentTimeMillis() - lastUpdated
            } else {
                0L
            }
            delay(1000)
        }
    }

    // Format elapsed time
    val hours = TimeUnit.MILLISECONDS.toHours(elapsedTime)
    val minutes = TimeUnit.MILLISECONDS.toMinutes(elapsedTime) % 60
    val seconds = TimeUnit.MILLISECONDS.toSeconds(elapsedTime) % 60
    val formattedTime = String.format("%02d:%02d:%02d", hours, minutes, seconds)

    // MitM Mode indicator and timer
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Mode indicator
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            val modeText = when (vpnMode) {
                VpnMode.BASE -> "MitM disabled"
                VpnMode.MITM_VPN -> "MitM-VPN enabled"
            }

            Text(
                text = modeText,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onBackground
            )
        }

        // Timer
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = formattedTime,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onBackground
            )
        }
    }
}

/**
 * Scanner button composable function.
 *
 * @param scanActive Whether the scan is active.
 * @param scanSetup Whether the scan setup is complete.
 * @param onStartScan Function to start the scan.
 * @param onStopScan Function to stop the scan.
 */

@Composable
fun ScannerButton(
    scanActive: Boolean,
    scanSetup: Boolean?,
    onStartScan: () -> Unit = {},
    onStopScan: () -> Unit = {}
) {
    // Launch button size
    val launchButtonSize = 64.dp

    // Create a derived state for the button UI
    val buttonState = when {
        scanSetup == true -> "SETUP"
        scanActive -> "ACTIVE"
        else -> "INACTIVE"
    }

    // Animated content to switch between states
    AnimatedContent(
        targetState = buttonState,
        transitionSpec = {
            // Configure different animations based on state transitions
            when {
                // Going to setup state (either direction)
                targetState == "SETUP" || initialState == "SETUP" -> {
                    fadeIn(animationSpec = tween(300)) togetherWith
                            fadeOut(animationSpec = tween(300))
                }
                // Going from inactive to active 
                initialState == "INACTIVE" && targetState == "ACTIVE" -> {
                    fadeIn(animationSpec = tween(300)) togetherWith
                            fadeOut(animationSpec = tween(300))
                }
                // Going from active to inactive
                else -> {
                    fadeIn(animationSpec = tween(300)) togetherWith
                            fadeOut(animationSpec = tween(300))
                }
            }
        },
        label = "Button State Animation"
    ) { state ->
        when (state) {
            "INACTIVE" -> {
                // IconButton for inactive state
                IconButton(
                    onClick = { onStartScan() },
                    modifier = Modifier
                        .size(launchButtonSize)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary),
                    enabled = true
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_play_32),
                        contentDescription = "Start scan",
                        modifier = Modifier.size(28.dp),
                        tint = MaterialTheme.colorScheme.onPrimary
                    )
                }
            }

            "SETUP" -> {
                // Progress indicator during setup
                Box(
                    modifier = Modifier
                        .size(launchButtonSize)
                        .background(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = CircleShape
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(launchButtonSize * 0.6f),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                        strokeWidth = 4.dp
                    )
                }
            }

            else -> {
                // IconButton for active state
                IconButton(
                    onClick = { onStopScan() },
                    modifier = Modifier
                        .size(launchButtonSize)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.surfaceVariant),
                    enabled = true
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_pause_32),
                        contentDescription = "Stop scan",
                        modifier = Modifier.size(28.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

/**
 * Convert a Unix timestamp to a human-readable date string.
 *
 * @param lastUpdated Unix timestamp.
 * @return Human-readable date string.
 */
private fun convertUnixToDate(lastUpdated: Long): String {
    val dateFormat = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault())
    val date = Date(lastUpdated)
    val calendar = Calendar.getInstance()
    calendar.time = date

    val today = Calendar.getInstance()
    val yesterday = Calendar.getInstance()
    yesterday.add(Calendar.DAY_OF_YEAR, -1)

    return when {
        calendar.get(Calendar.YEAR) == today.get(Calendar.YEAR) &&
                calendar.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR) -> {
            "Today " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
        }

        calendar.get(Calendar.YEAR) == yesterday.get(Calendar.YEAR) &&
                calendar.get(Calendar.DAY_OF_YEAR) == yesterday.get(Calendar.DAY_OF_YEAR) -> {
            "Yesterday " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
        }

        else -> dateFormat.format(date)
    }
}

/**
 * Preview for the TrafficScannerCard.
 */
@Preview(showBackground = true)
@Composable
fun TrafficScannerCardPreview() {
    HeimdallTheme {
        TrafficScannerCardContent(
            scanActive = false,
            scanSetup = false,
            lastUpdated = System.currentTimeMillis() - 3600000
        )
    }
}

/**
 * Preview for the TrafficScannerCard with active scan.
 */
@Preview(showBackground = true, name = "Traffic Scanner Active")
@Composable
fun TrafficScannerCardActivePreview() {
    HeimdallTheme {
        TrafficScannerCardContent(
            scanActive = true,
            scanSetup = false,
            lastUpdated = System.currentTimeMillis() - 3600000 // Show 1 hour of elapsed time
        )
    }
}

/**
 * Preview for the TrafficScannerCard with dark theme and MitM-VPN mode.
 */
@Preview(showBackground = true, name = "Traffic Scanner with MitM-VPN Mode and Dark Mode UI")
@Composable
fun TrafficScannerCardDarkPreview() {
    HeimdallTheme(useDarkTheme = true) {
        Box(
            modifier = Modifier
                .background(color = MaterialTheme.colorScheme.background)
        ) {
            TrafficScannerCardContent(
                scanActive = false,
                scanSetup = false,
                lastUpdated = System.currentTimeMillis(),
                vpnMode = VpnMode.MITM_VPN
            )
        }
    }
}

/**
 * Preview for the TrafficScannerCard with active scan and dark theme.
 */
@Preview(showBackground = true, name = "Traffic Scanner Active Dark Theme")
@Composable
fun TrafficScannerCardActiveDarkPreview() {
    HeimdallTheme(useDarkTheme = true) {
        Box(
            modifier = Modifier
                .background(color = MaterialTheme.colorScheme.background)
        ) {
            TrafficScannerCardContent(
                scanActive = true,
                scanSetup = false,
                lastUpdated = System.currentTimeMillis() - 7200000, // Show 2 hours of elapsed time
                vpnMode = VpnMode.MITM_VPN
            )
        }
    }
}