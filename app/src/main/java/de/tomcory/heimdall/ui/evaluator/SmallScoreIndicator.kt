package de.tomcory.heimdall.ui.evaluator

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.ui.theme.HeimdallTheme
import de.tomcory.heimdall.ui.theme.MonoFont

@Composable
fun SmallScoreIndicator(score: Double, size: Dp = 48.dp) {
    val risk = score.toRiskLevel()
    Box(
        modifier = Modifier
            .size(size)
            .clip(CircleShape)
            .background(risk.containerColor()),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = "${(score * 100).toInt()}",
            style = MaterialTheme.typography.labelLarge.copy(
                fontFamily = MonoFont,
                color = risk.onContainerColor(),
            ),
        )
    }
}

@Preview
@Composable
private fun SmallScoreIndicatorPreviewHigh() {
    HeimdallTheme { SmallScoreIndicator(score = 0.25) }
}

@Preview
@Composable
private fun SmallScoreIndicatorPreviewMedium() {
    HeimdallTheme { SmallScoreIndicator(score = 0.60) }
}

@Preview
@Composable
private fun SmallScoreIndicatorPreviewLow() {
    HeimdallTheme { SmallScoreIndicator(score = 0.88) }
}
