package de.tomcory.heimdall.ui.scanner

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.R
import de.tomcory.heimdall.ui.scanner.library.LibraryScannerCard
import de.tomcory.heimdall.ui.scanner.permission.PermissionScannerCard
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerCard
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import timber.log.Timber
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

@Composable
fun ScannerScreen() {
    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()

    // Function to show a snackbar message
    val showSnackbar: (String) -> Unit = { message ->
        // Launch a coroutine to show a snackbar
        coroutineScope.launch {
            snackbarHostState.showSnackbar(message)
        }
    }

    Scaffold(
        // Use the snackbarHostState in the Scaffold
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp),
            contentPadding = paddingValues
        ) {
            item {
                // Pass the showSnackbar function to the TrafficScannerCard
                TrafficScannerCard(onShowSnackbar = showSnackbar)
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
            }

            item {
                // Pass the showSnackbar function to the LibraryScannerCard
                LibraryScannerCard(onShowSnackbar = showSnackbar)
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
            }

            item {
                // Pass the showSnackbar function to the PermissionScannerCard
                PermissionScannerCard(onShowSnackbar = showSnackbar)
            }
        }
    }
}

@Composable
internal fun ScannerCard(
    title: String,
    lastUpdated: Long,
    scanActive: Boolean,
    onScan: () -> Unit,
    onScanCancel: () -> Unit,
    onShowSettings: () -> Unit,
    onShowDetails: () -> Unit,
    modifier: Modifier = Modifier,
    scanStartLabel: String = "Scan now",
    scanStopLabel: String = "Cancel",
    scanSetup: Boolean? = null,
    scanProgress: () -> Float = { -1f },
    onShowSnackbar: (String) -> Unit = {},
    content: @Composable (ColumnScope.() -> Unit)
) {

    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .then(modifier)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {

            // header with title, "last updated" subtitle and settings button
            ScannerCardHeader(
                title = title,
                lastUpdated = lastUpdated,
                scanActive = scanActive,
                onShowSettings = onShowSettings,
                scanSetup = scanSetup,
                scanProgress = scanProgress,
                onShowSnackbar = onShowSnackbar
            )

            // the scanner-specific content
            content()

            // footer with scan and details buttons
            ScannerCardFooter(
                onScan = onScan,
                onScanCancel = onScanCancel,
                onShowDetails = onShowDetails,
                scanActive = scanActive,
                scanSetup = scanSetup,
                scanStartLabel = scanStartLabel,
                scanStopLabel = scanStopLabel
            )
        }
    }
}

@Composable
private fun ScannerCardHeader(
    title: String,
    lastUpdated: Long,
    scanActive: Boolean,
    onShowSettings: () -> Unit,
    scanSetup: Boolean?,
    scanProgress: () -> Float,
    onShowSnackbar: (String) -> Unit
) {
    Row(
        horizontalArrangement = Arrangement.Start,
        modifier = Modifier
            .fillMaxWidth()
            .padding(0.dp, 0.dp, 0.dp, 8.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(0.dp, 0.dp, 0.dp, 4.dp)
            )

            AnimatedContent(
                targetState = scanSetup ?: scanActive,
                transitionSpec = { ContentTransform(fadeIn(), fadeOut()) },
                label = "ScannerActiveAnimation",
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(0.dp, 0.dp, 16.dp, 0.dp)
            ) { targetState ->
                if (targetState) {
                    if (scanProgress() >= 0) {
                        LinearProgressIndicator(
                            progress = scanProgress
                        )
                    } else {
                        LinearProgressIndicator()
                    }
                } else {
                    Text(
                        text = if(scanSetup != null && scanActive) "Scanner active" else "Last updated: ${convertUnixToDate(lastUpdated)}",
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
        }

        // give users a hint to disable the scanner before accessing the settings
        DisabledTooltip(
            targetState = scanActive,
            onShowSnackbar = onShowSnackbar,
            message = "Scanner-specific settings cannot be modified while the scanner is active."
        ) {
            FilledTonalIconButton(
                onClick = onShowSettings,
                enabled = !scanActive
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_settings_new),
                    contentDescription = "Settings icon"
                )
            }
        }
    }
}

@Composable
private fun ScannerCardFooter(
    onScan: () -> Unit,
    onScanCancel: () -> Unit,
    onShowDetails: () -> Unit,
    scanActive: Boolean,
    scanSetup: Boolean?,
    scanStartLabel: String,
    scanStopLabel: String,
) {
    Row(
        horizontalArrangement = Arrangement.End,
        modifier = Modifier
            .fillMaxWidth()
            .padding(0.dp, 8.dp, 0.dp, 0.dp)
    ) {
        Button(
            onClick = if (scanActive) onScanCancel else onScan,
            enabled = if (scanSetup != null) !scanSetup else true
        ) {
            Box(contentAlignment = Alignment.Center) {
                AnimatedContent(
                    targetState = scanActive,
                    transitionSpec = { ContentTransform(fadeIn(), fadeOut()) },
                    label = "Scan state transition"
                ) { targetState ->
                    Text(text = if (targetState) scanStopLabel else scanStartLabel)
                }
            }
        }

        Spacer(modifier = Modifier.width(8.dp))

        OutlinedButton(
            onClick = onShowDetails,
            enabled = if (scanSetup != null) !scanSetup else true
        ) {
            Text(text = "Details")
        }
    }
}

@Composable
fun DisabledTooltip(
    targetState: Boolean,
    onShowSnackbar: (String) -> Unit,
    message: String,
    content: @Composable BoxScope.() -> Unit
) {
    val coroutineScope = rememberCoroutineScope()

    Box(contentAlignment = Alignment.Center) {

        // the composable that gets disabled
        content()

        // Invisible clickable overlay
        if (targetState) {
            Box(
                modifier = Modifier
                    .matchParentSize() // Match the size of the IconButton
                    .pointerInput(Unit) {
                        detectTapGestures(
                            onPress = { /* No action on press to avoid visual feedback */
                            },
                            onTap = {
                                coroutineScope.launch {
                                    onShowSnackbar(message)
                                }
                            }
                        )
                    }
            )
        }
    }
}

private fun convertUnixToDate(lastUpdated: Long): String {
    val dateFormat = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault())
    val date = Date(lastUpdated * 1000) // Convert seconds to milliseconds
    val calendar = Calendar.getInstance()
    calendar.time = date

    // Get 'today' and 'yesterday' dates for comparison
    val today = Calendar.getInstance()
    val yesterday = Calendar.getInstance()
    yesterday.add(Calendar.DAY_OF_YEAR, -1)

    // Check if the date is today or yesterday
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

@Preview
@Composable
fun TrafficScannerCardPreview() {
    HeimdallTheme {
        TrafficScannerCard(onShowSnackbar = { })
    }
}

@Preview
@Composable
fun LibraryScannerCardPreview() {
    HeimdallTheme {
        LibraryScannerCard(onShowSnackbar = { })

    }
}

@Preview
@Composable
fun PermissionScannerCardPreview() {
    HeimdallTheme {
        PermissionScannerCard(onShowSnackbar = { })
    }
}