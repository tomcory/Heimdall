package de.tomcory.heimdall.ui.evaluator

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.EaseInOutExpo
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports

/**
 * Composable displaying the Score Card Element.
 * Derives the score information from a given [report].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScoreCard(report: ReportWithSubReports?) {

    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .padding(10.dp, 12.dp)
                .align(Alignment.CenterHorizontally)
        ) {

            Text(
                text = "Score",
                style = MaterialTheme.typography.titleLarge.merge(TextStyle(fontWeight = FontWeight.SemiBold)),
                modifier = Modifier.align(Alignment.CenterHorizontally)
            )

            Spacer(modifier = Modifier.height(8.dp))

            if (report != null) {
                ScoreChart(score = report.report.mainScore * 100)
            } else {
                Text(text = "No Score found in Database. Consider re-scanning", textAlign = TextAlign.Center)
            }
        }
    }
}


/**
 * CHart for displaying App [score].
 * Includes a arc meter with a gradient depending on the [colors] given.
 *
 */
@Composable
fun ScoreChart(
    score: Double,
    colors: List<Color> = listOf(
        Color.Red,
        Color.Green
    ),
    pathColor: Color = MaterialTheme.colorScheme.background,
    max: Double = 100.0,
    size: Dp = 220.dp,
    thickness: Dp = 15.dp,
    bottomGap: Float = 60f
) {

    val animateFloat = remember { Animatable(0f) }
    // animate meter arc growing when opened
    LaunchedEffect(animateFloat) {
        animateFloat.animateTo(
            targetValue = 1f,
            animationSpec = tween(durationMillis = 800, easing = EaseInOutExpo))
    }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(modifier = Modifier.size(size), contentAlignment = Alignment.Center) {


            val arcRadius = remember {
                size - thickness
            }
            val startAngle = remember { bottomGap / 2 }
            val sweepAngle: Float = remember {
                ((360 - bottomGap / 2 - startAngle) * (score / 100)).toFloat()
            }
            val colorArcOffset = remember { (bottomGap / 360) / 2 }
            // gradient
            val brush = Brush.sweepGradient(
                0f + colorArcOffset to colors[0],
                1f - colorArcOffset to colors[1]
            )
            Canvas(
                modifier = Modifier
                    .size(size)
            ) {

                // rotate 90 because gradient definition stats a 0f angle (right) - so everything is drawn on the side and then rotated
                rotate(90f) {
                    // draw meter "path" behind meter, showing missing potential for full score
                    drawArc(
                        color = pathColor,
                        startAngle = startAngle,
                        sweepAngle = (360 - bottomGap),
                        useCenter = false,
                        style = Stroke(width = thickness.toPx(), cap = StrokeCap.Round),
                        size = Size(arcRadius.toPx(), arcRadius.toPx()),
                        topLeft = Offset(
                            x = (size.toPx() - arcRadius.toPx()) / 2,
                            y = (size.toPx() - arcRadius.toPx()) / 2
                        ),
                        //alpha = 0f
                    )
                    // score meter arc
                    drawArc(
                        brush = brush,
                        startAngle = startAngle,
                        sweepAngle = sweepAngle * animateFloat.value,
                        useCenter = false,
                        style = Stroke(width = thickness.toPx(), cap = StrokeCap.Round),
                        size = Size(arcRadius.toPx(), arcRadius.toPx()),
                        topLeft = Offset(
                            x = (size.toPx() - arcRadius.toPx()) / 2,
                            y = (size.toPx() - arcRadius.toPx()) / 2
                        ),
                        //alpha = 0f
                    )
                }

            }
            // score numer text
            Box {
                Text(text = score.toInt().toString(), style = MaterialTheme.typography.displayLarge.merge(
                    TextStyle(brush = Brush.linearGradient(colors = listOf(Color.Cyan, Color(0xFF0066FF), Color(0xFFdd21d1))))
                ), fontWeight = FontWeight.SemiBold)
            }
            // score max text
            Box(modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(vertical = 12.dp)) {
                Text(text = "/ ${max.toInt()}", style = MaterialTheme.typography.labelLarge, color = Color.Gray)
            }
        }
    }
}

@Preview
@Composable
fun ScoreCardPreview(){
    Column {
        val reportSample = ReportWithSubReports(
            Report(appPackageName = "test.android.com", timestamp = 3000, mainScore = .8),
            listOf()
        )

        ScoreCard(report = reportSample)
        Spacer(modifier = Modifier.height(10.dp))
        ScoreCard(report = null)
    }
}

@Preview
@Composable
fun ScoreChartPreview() {
    ScoreChart(
        score = 76.0
    )
}