package de.tomcory.heimdall.ui.scanner

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.patrykandpatrick.vico.compose.cartesian.CartesianChartHost
import com.patrykandpatrick.vico.compose.cartesian.layer.rememberLineCartesianLayer
import com.patrykandpatrick.vico.compose.cartesian.rememberCartesianChart
import com.patrykandpatrick.vico.core.cartesian.data.CartesianChartModelProducer
import com.patrykandpatrick.vico.core.cartesian.data.lineSeries
import de.tomcory.heimdall.R
import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.ui.scanner.traffic.SessionStats
import de.tomcory.heimdall.ui.theme.MonoFont
import de.tomcory.heimdall.ui.theme.riskColors
import java.util.concurrent.TimeUnit

// ── Idle state ─────────────────────────────────────────────────────────────────

@Composable
fun IdleStateDashboard(
    lastSessionStats: SessionStats?,
    permLastUpdated: Long,
    libLastUpdated: Long,
    onScanPermissions: () -> Unit,
    onScanLibraries: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Spacer(modifier = Modifier.height(4.dp)) }

        item {
            if (lastSessionStats != null) {
                LastSessionSummaryCard(stats = lastSessionStats)
            } else {
                EmptySessionCard()
            }
        }

        // Contextual nudges — stale scans
        val now = System.currentTimeMillis()
        val permStale = permLastUpdated == 0L || (now - permLastUpdated) > 24 * 3_600_000L
        val libStale  = libLastUpdated  == 0L || (now - libLastUpdated)  > 7  * 86_400_000L

        if (permStale) {
            item {
                NudgeCard(
                    message = if (permLastUpdated == 0L) "Permissions have never been scanned."
                              else "Permission scan is over 24h old.",
                    actionLabel = "Scan now",
                    onAction = onScanPermissions,
                )
            }
        }
        if (libStale) {
            item {
                NudgeCard(
                    message = if (libLastUpdated == 0L) "Library scan has never been run."
                              else "Library scan is over 7 days old.",
                    actionLabel = "Scan now",
                    onAction = onScanLibraries,
                )
            }
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}

@Composable
private fun LastSessionSummaryCard(stats: SessionStats) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Last session",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                StatItem(label = "Duration",     value = formatDuration(stats.durationMs))
                StatItem(label = "Connections",  value = stats.connectionCount.toString())
                StatItem(label = "Unique hosts", value = stats.uniqueHosts.toString())
                StatItem(label = "Trackers",     value = stats.trackerCount.toString(),
                         highlight = stats.trackerCount > 0)
            }
        }
    }
}

@Composable
private fun EmptySessionCard() {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "No session recorded yet",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = "Start the VPN to begin monitoring traffic.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun StatItem(label: String, value: String, highlight: Boolean = false) {
    val rc = MaterialTheme.riskColors
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium.copy(
                fontFamily = MonoFont,
                color = if (highlight) rc.high else MaterialTheme.colorScheme.onSurface,
            ),
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall.copy(
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
        )
    }
}

@Composable
private fun NudgeCard(message: String, actionLabel: String, onAction: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f),
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onAction) {
                Text(actionLabel, style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

private fun formatDuration(ms: Long): String {
    val h = TimeUnit.MILLISECONDS.toHours(ms)
    val m = TimeUnit.MILLISECONDS.toMinutes(ms) % 60
    val s = TimeUnit.MILLISECONDS.toSeconds(ms) % 60
    return when {
        h > 0 -> "%dh %02dm".format(h, m)
        m > 0 -> "%dm %02ds".format(m, s)
        else  -> "${s}s"
    }
}

// ── Live state ─────────────────────────────────────────────────────────────────

@Composable
fun LiveDashboard(
    connections: List<Connection>,
    modifier: Modifier = Modifier,
) {
    val rc = MaterialTheme.riskColors

    // Bucket connections into per-second counts for the chart (last 60 seconds)
    val chartData = remember(connections) {
        buildChartData(connections, buckets = 60)
    }

    Column(modifier = modifier.fillMaxSize()) {
        // ── Connection count chart ─────────────────────────────────────────────
        if (connections.isNotEmpty()) {
            ConnectionChart(
                totalCounts = chartData.first,
                trackerCounts = chartData.second,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(160.dp)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            )
        } else {
            Box160dp()
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

        // ── Grouped connection feed ────────────────────────────────────────────
        val grouped = remember(connections) {
            connections.groupBy { it.initiatorPkg }
        }

        if (grouped.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = "Waiting for connections…",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                grouped.forEach { (pkg, conns) ->
                    item(key = "header_$pkg") {
                        Text(
                            text = pkg,
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(MaterialTheme.colorScheme.surfaceContainer)
                                .padding(horizontal = 16.dp, vertical = 6.dp),
                        )
                    }
                    items(conns.takeLast(20), key = { it.id }) { conn ->
                        ConnectionRow(conn = conn, trackerColor = rc.high)
                    }
                }
                item { Spacer(modifier = Modifier.height(16.dp)) }
            }
        }
    }
}

@Composable
private fun ConnectionRow(conn: Connection, trackerColor: androidx.compose.ui.graphics.Color) {
    val bgColor = if (conn.isTracker)
        trackerColor.copy(alpha = 0.06f)
    else
        MaterialTheme.colorScheme.surface

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(bgColor)
            .padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = conn.remoteHost?.ifEmpty { conn.remoteIp } ?: conn.remoteIp,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFont),
                maxLines = 1,
            )
            Text(
                text = conn.protocol.name,
                style = MaterialTheme.typography.labelSmall.copy(
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = MonoFont,
                ),
            )
        }
        if (conn.isTracker) {
            Icon(
                painter = painterResource(R.drawable.ic_cancel),
                contentDescription = "Tracker",
                tint = trackerColor,
                modifier = Modifier.size(14.dp),
            )
        }
        Spacer(modifier = Modifier.size(8.dp))
        Text(
            text = formatBytes(conn.bytesOut + conn.bytesIn),
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = MonoFont,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
        )
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)
}

@Composable
private fun ConnectionChart(
    totalCounts: List<Int>,
    trackerCounts: List<Int>,
    modifier: Modifier = Modifier,
) {
    val modelProducer = remember { CartesianChartModelProducer() }

    androidx.compose.runtime.LaunchedEffect(totalCounts, trackerCounts) {
        modelProducer.runTransaction {
            lineSeries {
                series(totalCounts.map { it.toFloat() })
                series(trackerCounts.map { it.toFloat() })
            }
        }
    }

    CartesianChartHost(
        chart = rememberCartesianChart(
            rememberLineCartesianLayer(),
        ),
        modelProducer = modelProducer,
        modifier = modifier,
    )
}

@Composable
private fun Box160dp() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .height(160.dp)
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = "No connections yet",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ── Data helpers ───────────────────────────────────────────────────────────────

private fun buildChartData(
    connections: List<Connection>,
    buckets: Int,
): Pair<List<Int>, List<Int>> {
    if (connections.isEmpty()) return Pair(List(buckets) { 0 }, List(buckets) { 0 })
    val now = System.currentTimeMillis()
    val windowMs = buckets * 1_000L
    val bucketMs = 1_000L
    val total   = IntArray(buckets)
    val tracker = IntArray(buckets)

    connections.forEach { conn ->
        val age = now - conn.initialTimestamp
        if (age in 0 until windowMs) {
            val idx = ((windowMs - age) / bucketMs).toInt().coerceIn(0, buckets - 1)
            total[idx]++
            if (conn.isTracker) tracker[idx]++
        }
    }
    return Pair(total.toList(), tracker.toList())
}

private fun formatBytes(bytes: Long): String = when {
    bytes < 1_024             -> "${bytes}B"
    bytes < 1_048_576         -> "${"%.1f".format(bytes / 1_024f)}KB"
    bytes < 1_073_741_824     -> "${"%.1f".format(bytes / 1_048_576f)}MB"
    else                      -> "${"%.1f".format(bytes / 1_073_741_824f)}GB"
}
