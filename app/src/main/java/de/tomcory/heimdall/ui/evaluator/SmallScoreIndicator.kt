package de.tomcory.heimdall.ui.evaluator

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

// old hardcoded colors:
// private val colors = mapOf("red" to Color(0xFF914406), "yellow" to Color(0xFF5e5006), "green" to Color(0xFF437a5a))

// colors for indicator
//TODO: make colors configurable
private val colors = mapOf(
    "red" to Color.Red,
    "yellow" to Color.Yellow,
    "green" to Color.Green
)

/**
 * Indicator Composable for [AppListItem] that shows app [score] in list entry.
 */
@Composable
fun SmallScoreIndicator(score:Double, size: Dp = 50.dp) {
    // color changes on score threshold - should respect threshold set in preference in the future
    val backgroundColor = remember {
        if (score > .75) colors["green"]!!
        else if (score > .50) colors["yellow"]!!
        else colors["red"]!!
    }

    Box(modifier = Modifier
        .size(size)
    ) {
        // colored cirlce
        Canvas(modifier = Modifier
            .fillMaxSize()
            .align(Alignment.Center)) {
            // val brush = Brush.radialGradient()
            drawCircle(
                color = backgroundColor,
            )
        }
        // score number
        Text(
            text = "${(score * 100).toInt()}",
            style = MaterialTheme.typography.headlineSmall.merge(
                TextStyle(color = MaterialTheme.colorScheme.onBackground, textAlign = TextAlign.Center)
            ),
            modifier = Modifier.align(Alignment.Center)
        )
    }

}

/**
 * Preview for [SmallScoreIndicator] with high score.
 */
@Preview
@Composable
fun SmallScoreIndicatorPreviewAcceptable() {
    SmallScoreIndicator(score = .90)
}

/**
 * Preview for [SmallScoreIndicator] with medium score.
 */
@Preview
@Composable
fun SmallScoreIndicatorPreviewQuestionable() {
    SmallScoreIndicator(score = .70)
}

/**
 * Preview for [SmallScoreIndicator] with low score.
 */
@Preview
@Composable
fun SmallScoreIndicatorPreviewUnacceptable() {
    SmallScoreIndicator(score = .23)
}