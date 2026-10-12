package de.tomcory.heimdall.ui.database

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import de.tomcory.heimdall.service.CaptureExportOptions
import de.tomcory.heimdall.service.CaptureExportOptions.Format
import de.tomcory.heimdall.service.CaptureExportOptions.SessionSelector
import de.tomcory.heimdall.service.CaptureExporter
import de.tomcory.heimdall.ui.theme.MonoFont
import timber.log.Timber

/**
 * Lets the user choose what to export, shows the export's progress, and then where the files
 * are, with the option to share them.
 */
@Composable
fun ExportDialog(
    state: ExportState,
    onExport: (CaptureExportOptions) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    var allSessions by remember { mutableStateOf(false) }
    var formats by remember { mutableStateOf(CaptureExportOptions.DEFAULT_FORMATS) }

    AlertDialog(
        onDismissRequest = { if (state !is ExportState.Running) onDismiss() },
        title = { Text("Export capture") },
        text = {
            Column {
                when (state) {
                    ExportState.Idle -> {
                        Text("Sessions", style = MaterialTheme.typography.labelLarge)
                        ChoiceRow(selected = !allSessions, label = "Latest session") { allSessions = false }
                        ChoiceRow(selected = allSessions, label = "All sessions") { allSessions = true }
                        Spacer(Modifier.height(12.dp))
                        Text("Files", style = MaterialTheme.typography.labelLarge)
                        FormatRow(Format.MESSAGES, "HTTP messages (JSON Lines)", formats) { formats = it }
                        FormatRow(Format.CONNECTIONS, "Connections (JSON Lines)", formats) { formats = it }
                        FormatRow(Format.SQLITE, "Copy of the whole database (SQLite)", formats) { formats = it }
                    }
                    ExportState.Running -> {
                        Text("Exporting…")
                        Spacer(Modifier.height(12.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                    is ExportState.Done -> {
                        val counts = state.result.counts.entries.joinToString(", ") { "${it.key.key}: ${it.value}" }
                        Text(if (counts.isEmpty()) "Export written to" else "Export written ($counts) to")
                        Spacer(Modifier.height(8.dp))
                        SelectionContainer {
                            Text(state.result.directory.absolutePath, fontFamily = MonoFont, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    is ExportState.Failed -> Text("The export failed: ${state.message}")
                }
            }
        },
        confirmButton = {
            when (state) {
                ExportState.Idle -> TextButton(
                    enabled = formats.isNotEmpty(),
                    onClick = {
                        onExport(CaptureExportOptions(if (allSessions) SessionSelector.All else SessionSelector.Latest, emptyList(), formats))
                    }
                ) { Text("Export") }
                is ExportState.Done -> TextButton(onClick = { share(context, state.result) }) { Text("Share") }
                else -> {}
            }
        },
        dismissButton = {
            if (state !is ExportState.Running) {
                TextButton(onClick = onDismiss) { Text(if (state is ExportState.Idle) "Cancel" else "Close") }
            }
        }
    )
}

@Composable
private fun ChoiceRow(selected: Boolean, label: String, onSelect: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onSelect),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = onSelect)
        Text(label, modifier = Modifier.padding(start = 4.dp))
    }
}

@Composable
private fun FormatRow(format: Format, label: String, chosen: Set<Format>, onChange: (Set<Format>) -> Unit) {
    val toggle = { onChange(if (format in chosen) chosen - format else chosen + format) }
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = toggle),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = format in chosen, onCheckedChange = { toggle() })
        Text(label, modifier = Modifier.padding(start = 4.dp))
    }
}

private fun share(context: Context, result: CaptureExporter.Result) {
    try {
        val uris = ArrayList(result.files.map { FileProvider.getUriForFile(context, "${context.packageName}.provider", it) })
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE)
            .setType("*/*")
            .putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(Intent.createChooser(intent, "Share capture export"))
    } catch (e: Exception) {
        Timber.e(e, "Error sharing the capture export")
    }
}
