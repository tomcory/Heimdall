package de.tomcory.heimdall.ui.database

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.patrykandpatrick.vico.compose.cartesian.CartesianChartHost
import com.patrykandpatrick.vico.compose.cartesian.layer.rememberLineCartesianLayer
import com.patrykandpatrick.vico.compose.cartesian.rememberCartesianChart
import com.patrykandpatrick.vico.core.cartesian.data.CartesianChartModelProducer
import com.patrykandpatrick.vico.core.cartesian.data.lineSeries
import de.tomcory.heimdall.ui.theme.MonoFont
import de.tomcory.heimdall.ui.theme.riskColors
import kotlinx.coroutines.launch

private val ANALYTICS_HEIGHT = 200.dp
private val CHART_HEIGHT = 140.dp

@Composable
fun DatabaseAnalytics(
    data: AnalyticsData,
    modifier: Modifier = Modifier,
) {
    val pages = listOf("Timeline", "Top Apps", "Trackers")
    val pagerState = rememberPagerState { pages.size }
    val scope = rememberCoroutineScope()

    Column(modifier = modifier) {
        ScrollableTabRow(
            selectedTabIndex = pagerState.currentPage,
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
            edgePadding = 16.dp,
        ) {
            pages.forEachIndexed { index, title ->
                Tab(
                    selected = pagerState.currentPage == index,
                    onClick = { scope.launch { pagerState.animateScrollToPage(index) } },
                    text = {
                        Text(
                            text = title,
                            style = MaterialTheme.typography.labelMedium,
                        )
                    },
                )
            }
        }

        HorizontalPager(
            state = pagerState,
            modifier = Modifier
                .fillMaxWidth()
                .height(ANALYTICS_HEIGHT),
        ) { page ->
            when (page) {
                0 -> TimelinePanel(data.timelineBuckets)
                1 -> RankedListPanel(
                    items = data.topApps,
                    emptyText = "No connections recorded",
                    useMonoLabel = true,
                )
                2 -> RankedListPanel(
                    items = data.topTrackerHosts,
                    emptyText = "No tracker connections recorded",
                    useMonoLabel = true,
                    barColor = MaterialTheme.riskColors.high,
                )
            }
        }
    }
}

// ── Timeline ───────────────────────────────────────────────────────────────────

@Composable
private fun TimelinePanel(buckets: List<Int>) {
    if (buckets.isEmpty() || buckets.all { it == 0 }) {
        EmptyAnalyticsBox("No traffic data in the last 30 minutes")
        return
    }

    val modelProducer = remember { CartesianChartModelProducer() }

    LaunchedEffect(buckets) {
        modelProducer.runTransaction {
            lineSeries { series(buckets.map { it.toFloat() }) }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(
            text = "Connections per minute · last 30 min",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        CartesianChartHost(
            chart = rememberCartesianChart(rememberLineCartesianLayer()),
            modelProducer = modelProducer,
            modifier = Modifier
                .fillMaxWidth()
                .height(CHART_HEIGHT),
        )
    }
}

// ── Ranked bar list ────────────────────────────────────────────────────────────

@Composable
private fun RankedListPanel(
    items: List<Pair<String, Int>>,
    emptyText: String,
    useMonoLabel: Boolean = false,
    barColor: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.primary,
) {
    if (items.isEmpty()) {
        EmptyAnalyticsBox(emptyText)
        return
    }

    val maxCount = items.maxOf { it.second }.coerceAtLeast(1).toFloat()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items.forEach { (label, count) ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = label,
                    style = if (useMonoLabel)
                        MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont)
                    else
                        MaterialTheme.typography.labelSmall,
                    modifier = Modifier.width(140.dp),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.width(8.dp))
                LinearProgressIndicator(
                    progress = { count / maxCount },
                    modifier = Modifier.weight(1f).height(6.dp),
                    color = barColor,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = count.toString(),
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFont),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun EmptyAnalyticsBox(message: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(ANALYTICS_HEIGHT),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = message,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
