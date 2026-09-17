package de.tomcory.heimdall.ui.scanner

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.R
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * Generic scanner card template used by LibraryScannerCard and PermissionScannerCard.
 * Not currently rendered in ScannerScreen — the control strip handles these scanners directly.
 */
@Composable
internal fun ScannerCard(
    title: String,
    lastUpdated: Long,
    scanActive: Boolean,
    onScan: () -> Unit,
    onScanCancel: () -> Unit,
    onShowDetails: () -> Unit,
    modifier: Modifier = Modifier,
    scanStartLabel: String = "Scan now",
    scanStopLabel: String = "Cancel",
    scanSetup: Boolean? = null,
    scanProgress: () -> Float = { -1f },
    onShowSnackbar: (String) -> Unit = {},
    infoDialogContent: @Composable () -> Unit,
    content: @Composable (ColumnScope.((String) -> Unit) -> Unit),
) {
    var showInfoDialog by remember { mutableStateOf(false) }

    ElevatedCard(modifier = Modifier.fillMaxWidth().then(modifier)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(text = title, style = MaterialTheme.typography.titleLarge)
                    AnimatedContent(
                        targetState = scanSetup ?: scanActive,
                        transitionSpec = { ContentTransform(fadeIn(), fadeOut()) },
                        label = "scanner-header",
                        modifier = Modifier.fillMaxWidth().padding(end = 16.dp),
                    ) { active ->
                        if (active) {
                            val progress = scanProgress()
                            if (progress >= 0) LinearProgressIndicator(progress = { progress })
                            else LinearProgressIndicator()
                        } else {
                            Text(
                                text = "Last updated: ${convertUnixToDate(lastUpdated)}",
                                style = MaterialTheme.typography.labelSmall,
                            )
                        }
                    }
                }
                IconButton(onClick = { showInfoDialog = true }) {
                    Icon(painterResource(R.drawable.ic_help), contentDescription = "Info")
                }
            }

            content(onShowSnackbar)

            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = androidx.compose.foundation.layout.Arrangement.End,
            ) {
                Button(
                    onClick = if (scanActive) onScanCancel else onScan,
                    enabled = if (scanSetup != null) !scanSetup else true,
                ) {
                    AnimatedContent(
                        targetState = scanActive,
                        transitionSpec = { ContentTransform(fadeIn(), fadeOut()) },
                        label = "scan-button",
                    ) { active ->
                        Text(if (active) scanStopLabel else scanStartLabel)
                    }
                }
                Spacer(modifier = Modifier.width(8.dp))
                OutlinedButton(
                    onClick = onShowDetails,
                    enabled = if (scanSetup != null) !scanSetup else true,
                ) { Text("Details") }
            }
        }
    }

    if (showInfoDialog) {
        AlertDialog(
            onDismissRequest = { showInfoDialog = false },
            title = { Text(title) },
            text = { infoDialogContent() },
            confirmButton = {
                TextButton(onClick = { showInfoDialog = false }) { Text("Got it") }
            },
        )
    }
}

@Composable
fun ScannerInfoDialog(
    title: String,
    onDismissRequest: () -> Unit,
    content: @Composable () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismissRequest,
        title = { Text(title) },
        text = { content() },
        confirmButton = {
            TextButton(onClick = onDismissRequest) { Text("Got it") }
        },
    )
}

internal fun convertUnixToDate(ts: Long): String {
    val dateFormat = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault())
    val date = Date(ts)
    val cal = Calendar.getInstance().apply { time = date }
    val today = Calendar.getInstance()
    val yesterday = Calendar.getInstance().also { it.add(Calendar.DAY_OF_YEAR, -1) }
    return when {
        cal.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR) ->
            "Today " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
        cal.get(Calendar.DAY_OF_YEAR) == yesterday.get(Calendar.DAY_OF_YEAR) ->
            "Yesterday " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
        else -> dateFormat.format(date)
    }
}
