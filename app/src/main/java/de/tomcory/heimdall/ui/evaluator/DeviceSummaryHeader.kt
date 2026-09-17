package de.tomcory.heimdall.ui.evaluator

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import de.tomcory.heimdall.ui.theme.MonoFont
import de.tomcory.heimdall.ui.theme.riskColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DeviceSummaryHeader(
    stats: DeviceStats,
    activeFilter: ScoreFilter,
    onFilterTrackers: () -> Unit,
    onFilterDangerousPerms: () -> Unit,
    onRescan: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        RiskRing(stats = stats, size = 160.dp)

        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
        ) {
            StatChip(
                label = "Trackers",
                value = stats.appsWithTrackers.toString(),
                selected = activeFilter == ScoreFilter.TRACKERS,
                onClick = onFilterTrackers,
            )
            StatChip(
                label = "Dangerous perms",
                value = stats.appsWithDangerousPerms.toString(),
                selected = activeFilter == ScoreFilter.DANGEROUS_PERMS,
                onClick = onFilterDangerousPerms,
            )
            StatChip(
                label = "Last scanned",
                value = stats.lastScannedTimestamp?.let { formatTimestamp(it) } ?: "Never",
                selected = false,
                onClick = onRescan,
            )
        }
    }
}

@Composable
private fun RiskRing(
    stats: DeviceStats,
    size: Dp = 160.dp,
    thickness: Dp = 18.dp,
) {
    val rc = MaterialTheme.riskColors
    val total = stats.totalApps.coerceAtLeast(1).toFloat()

    // Segments: HIGH, MEDIUM, LOW, UNKNOWN
    data class Segment(val sweep: Float, val color: Color)
    val segments = listOf(
        Segment((stats.highRiskCount / total) * 360f, rc.high),
        Segment((stats.mediumRiskCount / total) * 360f, rc.medium),
        Segment((stats.lowRiskCount / total) * 360f, rc.low),
        Segment((stats.unknownCount / total) * 360f, rc.unknown),
    ).filter { it.sweep > 0f }

    val animProgress = remember { Animatable(0f) }
    LaunchedEffect(stats.totalApps) {
        animProgress.animateTo(
            targetValue = 1f,
            animationSpec = spring(
                dampingRatio = 0.65f,
                stiffness = Spring.StiffnessLow,
            ),
        )
    }

    Box(
        modifier = Modifier.size(size),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(modifier = Modifier.size(size)) {
            val arcSize = size.toPx() - thickness.toPx()
            val topLeft = Offset(
                x = (size.toPx() - arcSize) / 2f,
                y = (size.toPx() - arcSize) / 2f,
            )
            val stroke = Stroke(width = thickness.toPx(), cap = StrokeCap.Butt)

            // Track background
            drawArc(
                color = rc.unknownContainer,
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                style = stroke,
                size = Size(arcSize, arcSize),
                topLeft = topLeft,
            )

            // Animate segments
            var startAngle = -90f
            segments.forEach { seg ->
                val animatedSweep = seg.sweep * animProgress.value
                drawArc(
                    color = seg.color,
                    startAngle = startAngle,
                    sweepAngle = animatedSweep,
                    useCenter = false,
                    style = stroke,
                    size = Size(arcSize, arcSize),
                    topLeft = topLeft,
                )
                startAngle += animatedSweep
            }
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = stats.totalApps.toString(),
                style = MaterialTheme.typography.displaySmall.copy(fontFamily = MonoFont),
            )
            Text(
                text = "apps",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun StatChip(
    label: String,
    value: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = value,
                    style = MaterialTheme.typography.labelLarge.copy(fontFamily = MonoFont),
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
            selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
    )
}

private fun formatTimestamp(timestamp: Long): String {
    val now = System.currentTimeMillis()
    val diff = now - timestamp
    return when {
        diff < 60_000          -> "just now"
        diff < 3_600_000       -> "${diff / 60_000}m ago"
        diff < 86_400_000      -> "${diff / 3_600_000}h ago"
        else                   -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(timestamp))
    }
}

@Preview(showBackground = true)
@Composable
private fun DeviceSummaryHeaderPreview() {
    HeimdallTheme {
        DeviceSummaryHeader(
            stats = DeviceStats(
                totalApps = 20,
                highRiskCount = 4,
                mediumRiskCount = 8,
                lowRiskCount = 6,
                unknownCount = 2,
                appsWithTrackers = 12,
                appsWithDangerousPerms = 9,
                lastScannedTimestamp = System.currentTimeMillis() - 7_200_000,
            ),
            activeFilter = ScoreFilter.NONE,
            onFilterTrackers = {},
            onFilterDangerousPerms = {},
            onRescan = {},
        )
    }
}
