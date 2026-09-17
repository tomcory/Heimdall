package de.tomcory.heimdall.ui.evaluator

import android.graphics.drawable.Drawable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Image
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.hilt.navigation.compose.hiltViewModel
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import de.tomcory.heimdall.R
import de.tomcory.heimdall.core.database.entity.AppWithReportsAndSubReports
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import de.tomcory.heimdall.ui.theme.MonoFont
import kotlinx.coroutines.launch

@Composable
fun ScoreScreen(
    viewModel: ScoreViewModel = hiltViewModel(),
) {
    val apps by viewModel.apps.collectAsState()
    val deviceStats by viewModel.deviceStats.collectAsState()
    val activeFilter by viewModel.activeFilter.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.surface,
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            DeviceSummaryHeader(
                stats = deviceStats,
                activeFilter = activeFilter,
                onFilterTrackers = { viewModel.setFilter(ScoreFilter.TRACKERS) },
                onFilterDangerousPerms = { viewModel.setFilter(ScoreFilter.DANGEROUS_PERMS) },
                onRescan = { scope.launch { viewModel.scoreAllApps() } },
            )

            HorizontalDivider()

            SectionedAppList(
                apps = apps,
                snackbarHostState = snackbarHostState,
                viewModel = viewModel,
            )
        }
    }
}

// ── Sectioned list ─────────────────────────────────────────────────────────────

@Composable
private fun SectionedAppList(
    apps: List<AppWithReportsAndSubReports>,
    snackbarHostState: SnackbarHostState,
    viewModel: ScoreViewModel,
) {
    val scope = rememberCoroutineScope()

    if (apps.isEmpty()) {
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "No apps analysed yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = "Tap the timestamp chip to run a scan.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        return
    }

    val grouped = remember(apps) {
        val map = linkedMapOf(
            RiskLevel.HIGH    to mutableListOf<AppWithReportsAndSubReports>(),
            RiskLevel.MEDIUM  to mutableListOf(),
            RiskLevel.LOW     to mutableListOf(),
            RiskLevel.UNKNOWN to mutableListOf(),
        )
        apps.forEach { app ->
            val score = app.getLatestReport()?.report?.mainScore
            map[score.toRiskLevel()]!!.add(app)
        }
        map.filter { it.value.isNotEmpty() }
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        grouped.forEach { (risk, sectionApps) ->
            item(key = risk.name) {
                SectionHeader(risk = risk, count = sectionApps.size)
            }
            items(sectionApps, key = { it.app.packageName }) { appWithReports ->
                var showDetail by remember { mutableStateOf(false) }
                var expanded by remember { mutableStateOf(false) }

                AppRow(
                    appWithReports = appWithReports,
                    expanded = expanded,
                    onToggle = { expanded = !expanded },
                    onViewDetail = {
                        scope.launch {
                            viewModel.selectApp(appWithReports)
                            showDetail = true
                        }
                    },
                    onRescan = {
                        scope.launch { viewModel.scoreApp(appWithReports.app.packageName) }
                    },
                    getIcon = viewModel::getAppIcon,
                )

                if (showDetail) {
                    Dialog(
                        onDismissRequest = { showDetail = false },
                        properties = DialogProperties(usePlatformDefaultWidth = false),
                    ) {
                        AppScoreScreen(
                            snackbarHostState = snackbarHostState,
                            onDismissRequest = { showDetail = false },
                        )
                    }
                }
            }
        }
        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}

@Composable
private fun SectionHeader(risk: RiskLevel, count: Int) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(risk.containerColor().copy(alpha = 0.25f))
            .padding(horizontal = 16.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = risk.label(),
            style = MaterialTheme.typography.labelMedium.copy(
                fontWeight = FontWeight.SemiBold,
                color = risk.color(),
            ),
        )
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.labelMedium.copy(
                fontFamily = MonoFont,
                color = risk.color(),
            ),
        )
    }
}

// ── Expandable app row ─────────────────────────────────────────────────────────

@Composable
private fun AppRow(
    appWithReports: AppWithReportsAndSubReports,
    expanded: Boolean,
    onToggle: () -> Unit,
    onViewDetail: () -> Unit,
    onRescan: () -> Unit,
    getIcon: suspend (String) -> Drawable,
) {
    val app = appWithReports.app
    val latestReport = appWithReports.getLatestReport()
    val score = latestReport?.report?.mainScore
    val risk = score.toRiskLevel()

    var icon: Drawable? by remember { mutableStateOf(null) }
    LaunchedEffect(app.packageName) {
        icon = getIcon(app.packageName)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle),
    ) {
        // Compact row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val painter = if (icon == null) {
                painterResource(R.drawable.ic_cancel)
            } else {
                rememberDrawablePainter(icon)
            }
            Image(
                painter = painter,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
            )

            Spacer(modifier = Modifier.width(12.dp))

            Text(
                text = app.label,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )

            Spacer(modifier = Modifier.width(8.dp))

            if (score != null) {
                SmallScoreIndicator(score = score, size = 40.dp)
            }

            Spacer(modifier = Modifier.width(4.dp))

            Icon(
                imageVector = if (expanded) Icons.Filled.KeyboardArrowUp
                              else Icons.Filled.KeyboardArrowDown,
                contentDescription = if (expanded) "Collapse" else "Expand",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
        }

        // Expanded card
        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically(
                animationSpec = spring(dampingRatio = 0.7f, stiffness = Spring.StiffnessMedium),
            ) + fadeIn(),
            exit = shrinkVertically(
                animationSpec = spring(dampingRatio = 0.7f, stiffness = Spring.StiffnessMedium),
            ) + fadeOut(),
        ) {
            AppExpandedCard(
                report = latestReport,
                risk = risk,
                onViewDetail = onViewDetail,
                onRescan = onRescan,
            )
        }

        HorizontalDivider(
            color = MaterialTheme.colorScheme.outlineVariant,
            thickness = 0.5.dp,
        )
    }
}

@Composable
private fun AppExpandedCard(
    report: ReportWithSubReports?,
    risk: RiskLevel,
    onViewDetail: () -> Unit,
    onRescan: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            if (report != null) {
                // Module score chips row
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    report.subReports.forEach { sub ->
                        ModuleScoreChip(
                            moduleName = sub.module,
                            score = sub.score.toDouble(),
                        )
                    }
                }
            } else {
                Text(
                    text = "Not yet analysed",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Quick actions
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                TextButton(onClick = onRescan) {
                    Text("Rescan", style = MaterialTheme.typography.labelMedium)
                }
                Spacer(modifier = Modifier.width(4.dp))
                TextButton(onClick = onViewDetail) {
                    Text("Full report →", style = MaterialTheme.typography.labelMedium)
                }
            }
        }
    }
}

@Composable
private fun ModuleScoreChip(moduleName: String, score: Double) {
    val risk = score.toRiskLevel()
    val label = when {
        moduleName.contains("Permission", ignoreCase = true) -> "Perms"
        moduleName.contains("Tracker",   ignoreCase = true) -> "Trackers"
        moduleName.contains("Privacy",   ignoreCase = true) -> "Policy"
        else -> moduleName.take(6)
    }
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .background(
                color = risk.containerColor(),
                shape = MaterialTheme.shapes.small,
            )
            .padding(horizontal = 10.dp, vertical = 6.dp),
    ) {
        Text(
            text = "${(score * 100).toInt()}",
            style = MaterialTheme.typography.labelLarge.copy(
                fontFamily = MonoFont,
                color = risk.onContainerColor(),
            ),
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall.copy(
                color = risk.onContainerColor(),
            ),
        )
    }
}

@Preview(showBackground = true)
@Composable
private fun ScoreScreenPreview() {
    HeimdallTheme { ScoreScreen() }
}
