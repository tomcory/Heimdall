package de.tomcory.heimdall.ui.evaluator

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import de.tomcory.heimdall.ui.theme.MonoFont
import de.tomcory.heimdall.ui.theme.riskColors

@Composable
fun ScoreCard(report: ReportWithSubReports?) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "Privacy Score",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(modifier = Modifier.height(16.dp))
            if (report != null) {
                ScoreRing(score = report.report.mainScore)
            } else {
                Text(
                    text = "Not yet analysed.\nTap ⋮ → Rescan to generate a score.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

@Composable
fun ScoreRing(
    score: Double,
    size: Dp = 180.dp,
    thickness: Dp = 16.dp,
) {
    val risk = score.toRiskLevel()
    val rc = MaterialTheme.riskColors

    val animProgress = remember { Animatable(0f) }
    LaunchedEffect(score) {
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
            val stroke = Stroke(width = thickness.toPx(), cap = StrokeCap.Round)
            val sweep = (score * 360f * animProgress.value).toFloat()

            // Track
            drawArc(
                color = rc.unknownContainer,
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                style = stroke,
                size = Size(arcSize, arcSize),
                topLeft = topLeft,
            )
            // Score arc
            drawArc(
                color = when (risk) {
                    RiskLevel.HIGH    -> rc.high
                    RiskLevel.MEDIUM  -> rc.medium
                    RiskLevel.LOW     -> rc.low
                    RiskLevel.UNKNOWN -> rc.unknown
                },
                startAngle = -90f,
                sweepAngle = sweep,
                useCenter = false,
                style = stroke,
                size = Size(arcSize, arcSize),
                topLeft = topLeft,
            )
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "${(score * 100).toInt()}",
                style = MaterialTheme.typography.displaySmall.copy(
                    fontFamily = MonoFont,
                    color = risk.color(),
                ),
            )
            Text(
                text = "/ 100",
                style = MaterialTheme.typography.labelMedium.copy(
                    fontFamily = MonoFont,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )
        }
    }
}

@Preview
@Composable
private fun ScoreCardPreview() {
    HeimdallTheme {
        Column {
            ScoreCard(
                report = ReportWithSubReports(
                    Report(appPackageName = "test.android.com", timestamp = 3000, mainScore = 0.8),
                    listOf(),
                ),
            )
            Spacer(modifier = Modifier.height(10.dp))
            ScoreCard(report = null)
        }
    }
}

@Preview
@Composable
private fun ScoreRingPreview() {
    HeimdallTheme { ScoreRing(score = 0.76) }
}
