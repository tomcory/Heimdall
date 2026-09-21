package de.tomcory.heimdall.ui.database

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import de.tomcory.heimdall.ui.theme.MonoFont
import de.tomcory.heimdall.ui.theme.riskColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DatabaseScreen(
    viewModel: DatabaseViewModel = hiltViewModel(),
) {
    val filteredConnections by viewModel.filteredConnections.collectAsState()
    val analyticsData by viewModel.analyticsData.collectAsState()
    val activeFilter by viewModel.activeFilter.collectAsState()

    Scaffold(
        containerColor = MaterialTheme.colorScheme.surface,
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            // ── Analytics section ──────────────────────────────────────────────
            DatabaseAnalytics(data = analyticsData)

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            // ── Filter bar ─────────────────────────────────────────────────────
            FilterBar(
                activeFilter = activeFilter,
                onFilterChange = viewModel::setFilter,
            )

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            // ── Connection log ─────────────────────────────────────────────────
            if (filteredConnections.isEmpty()) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text(
                        text = if (activeFilter == DbFilter.ALL) "No connections captured yet."
                               else "No connections match the active filter.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(filteredConnections, key = { it.id }) { conn ->
                        val expanded = viewModel.isExpanded(conn.id)
                        ConnectionLogRow(
                            connection = conn,
                            expanded = expanded,
                            onToggle = { viewModel.expandConnection(conn.id) },
                            viewModel = viewModel,
                        )
                    }
                    item { Spacer(modifier = Modifier.height(16.dp)) }
                }
            }
        }
    }
}

// ── Filter bar ─────────────────────────────────────────────────────────────────

@Composable
private fun FilterBar(
    activeFilter: DbFilter,
    onFilterChange: (DbFilter) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        DbFilter.entries.forEach { filter ->
            val label = when (filter) {
                DbFilter.ALL           -> "All"
                DbFilter.TRACKERS_ONLY -> "Trackers"
                DbFilter.TCP           -> "TCP"
                DbFilter.UDP           -> "UDP"
            }
            FilterChip(
                selected = activeFilter == filter,
                onClick = { onFilterChange(filter) },
                label = { Text(label, style = MaterialTheme.typography.labelMedium) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            )
        }
    }
}

// ── Connection log row ─────────────────────────────────────────────────────────

@Composable
private fun ConnectionLogRow(
    connection: Connection,
    expanded: Boolean,
    onToggle: () -> Unit,
    viewModel: DatabaseViewModel,
) {
    val rc = MaterialTheme.riskColors
    val bgColor = if (connection.isTracker)
        rc.high.copy(alpha = 0.05f)
    else
        MaterialTheme.colorScheme.surface

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(bgColor)
            .clickable(onClick = onToggle),
    ) {
        // Compact row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // Protocol badge
            Surface(
                color = MaterialTheme.colorScheme.secondaryContainer,
                shape = MaterialTheme.shapes.extraSmall,
                modifier = Modifier.width(36.dp),
            ) {
                Text(
                    text = connection.protocol.name.take(3).uppercase(),
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont),
                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                    maxLines = 1,
                )
            }

            Spacer(modifier = Modifier.width(10.dp))

            // Host + package
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = connection.remoteHost?.ifEmpty { connection.remoteIp } ?: connection.remoteIp,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFont),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = connection.initiatorPkg,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Tracker dot
            if (connection.isTracker) {
                Text(
                    text = "●",
                    style = MaterialTheme.typography.labelSmall,
                    color = rc.high,
                )
                Spacer(modifier = Modifier.width(4.dp))
            }

            // Bytes
            Text(
                text = formatBytes(connection.bytesOut + connection.bytesIn),
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.width(8.dp))

            // Timestamp
            Text(
                text = relativeTime(connection.initialTimestamp),
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // Expanded detail
        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically(spring(dampingRatio = 0.7f, stiffness = Spring.StiffnessMedium)) + fadeIn(),
            exit = shrinkVertically(spring(dampingRatio = 0.7f, stiffness = Spring.StiffnessMedium)) + fadeOut(),
        ) {
            ConnectionDetail(connection = connection, viewModel = viewModel)
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)
    }
}

// ── Inline connection detail ───────────────────────────────────────────────────

@Composable
private fun ConnectionDetail(
    connection: Connection,
    viewModel: DatabaseViewModel,
) {
    val requests by viewModel.requestsFor(connection.id)
        .collectAsState(initial = emptyList())

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            // Connection metadata
            ConnectionMetadataRow("Remote", "${connection.remoteHost ?: "unresolved"}:${connection.remotePort}")
            ConnectionMetadataRow("Protocol", connection.protocol.name)
            ConnectionMetadataRow("↑ Out", formatBytes(connection.bytesOut))
            ConnectionMetadataRow("↓ In", formatBytes(connection.bytesIn))

            if (requests.isEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "No HTTP requests intercepted\n(VPN-only mode or no MitM)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Spacer(modifier = Modifier.height(8.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Requests (${requests.size})",
                    style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                )
                requests.forEach { req ->
                    RequestRow(request = req, viewModel = viewModel)
                }
            }
        }
    }
}

@Composable
private fun ConnectionMetadataRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}

@Composable
private fun RequestRow(request: Request, viewModel: DatabaseViewModel) {
    val statusCode by produceState<Int?>(null, request.id) {
        value = viewModel.responseStatusFor(request.id)
    }

    val statusColor = when {
        statusCode == null         -> MaterialTheme.colorScheme.onSurfaceVariant
        statusCode!! < 300         -> MaterialTheme.riskColors.low
        statusCode!! < 400         -> MaterialTheme.colorScheme.primary
        else                       -> MaterialTheme.riskColors.high
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Method badge
        Surface(
            color = MaterialTheme.colorScheme.secondaryContainer,
            shape = MaterialTheme.shapes.extraSmall,
        ) {
            Text(
                text = request.method.take(6),
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont),
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
            )
        }

        Spacer(modifier = Modifier.width(8.dp))

        // Path
        Text(
            text = request.remotePath.ifEmpty { "/" },
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont),
            modifier = Modifier.weight(1f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        // Status code
        if (statusCode != null) {
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = statusCode.toString(),
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = MonoFont,
                    color = statusColor,
                ),
            )
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

private fun formatBytes(bytes: Long): String = when {
    bytes < 1_024         -> "${bytes}B"
    bytes < 1_048_576     -> "${"%.1f".format(bytes / 1_024f)}KB"
    bytes < 1_073_741_824 -> "${"%.1f".format(bytes / 1_048_576f)}MB"
    else                  -> "${"%.1f".format(bytes / 1_073_741_824f)}GB"
}

private fun relativeTime(ts: Long): String {
    val diff = System.currentTimeMillis() - ts
    return when {
        diff < 60_000       -> "${diff / 1_000}s"
        diff < 3_600_000    -> "${diff / 60_000}m"
        diff < 86_400_000   -> "${diff / 3_600_000}h"
        else                -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(ts))
    }
}

@Preview(showBackground = true)
@Composable
private fun DatabaseScreenPreview() {
    HeimdallTheme { DatabaseScreen() }
}
