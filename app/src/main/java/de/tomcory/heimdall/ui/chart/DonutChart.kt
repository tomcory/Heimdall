package de.tomcory.heimdall.ui.chart

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

@Preview
@Composable
fun DonutChartPreview() {
    DonutChart(
        values = listOf(30f, 70f, 20f),
        colors = listOf(
            MaterialTheme.colorScheme.primary,
            MaterialTheme.colorScheme.secondary,
            MaterialTheme.colorScheme.tertiary),
        legend = listOf("Dangerous", "Normal", "Signature"),
    )
}

@Composable
fun DonutChart(
    values: List<Float>,
    colors: List<Color>,
    legend: List<String>,
    size: Dp = 240.dp,
    thickness: Dp = 20.dp,
    backgroundCircleColor: Color = Color.LightGray.copy(alpha = 0.3f)
) {

    val total = values.sum()
    // Convert each value to angle
    val sweepAngles = values.map {
        360 * it / total
    }

    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(modifier = Modifier.size(size), contentAlignment = Alignment.Center) {
            Canvas(
                modifier = Modifier
                    .size(size)
            ) {

                val arcRadius = size.toPx() - thickness.toPx()
                var startAngle = -90f

                drawCircle(
                    color = backgroundCircleColor,
                    radius = arcRadius / 2,
                    style = Stroke(width = thickness.toPx(), cap = StrokeCap.Butt)
                )

                for (i in values.indices) {

                    //arcRadius -= gapBetweenCircles.toPx()

                    drawArc(
                        color = colors[i],
                        startAngle = startAngle,
                        sweepAngle = sweepAngles[i] * -1,
                        useCenter = false,
                        style = Stroke(width = thickness.toPx(), cap = StrokeCap.Round),
                        size = Size(arcRadius, arcRadius),
                        topLeft = Offset(
                            x = (size.toPx() - arcRadius) / 2,
                            y = (size.toPx() - arcRadius) / 2
                        )
                    )

                    startAngle -= sweepAngles[i]

                }

                drawArc(
                    color = colors[0],
                    startAngle = startAngle,
                    sweepAngle = sweepAngles[0] * -0.5f,
                    useCenter = false,
                    style = Stroke(width = thickness.toPx(), cap = StrokeCap.Round),
                    size = Size(arcRadius, arcRadius),
                    topLeft = Offset(
                        x = (size.toPx() - arcRadius) / 2,
                        y = (size.toPx() - arcRadius) / 2
                    )
                )

            }

            Box {
                Text(text = stringifyFloat(total), style = MaterialTheme.typography.displayMedium)
            }
        }

        Spacer(modifier = Modifier.height(4.dp + (0.5f * thickness.value).dp))

        Row(horizontalArrangement = Arrangement.SpaceAround, modifier = Modifier.fillMaxWidth()) {
            for (i in values.indices) {
                DisplayLegend(value = values[values.size - 1 - i], color = colors[values.size - 1 - i], legend = legend[values.size - 1 - i])
            }
        }
    }
}

@Composable
fun DisplayLegend(value: Float, color: Color, legend: String) {

    Row(
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(28.dp)
                .background(color = color, shape = CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Text(text = stringifyFloat(value), color = MaterialTheme.colorScheme.onPrimary)
        }

        Spacer(modifier = Modifier.width(8.dp))

        Text(
            text = legend
        )
    }
}

fun stringifyFloat(value: Float) : String {
    return if(value.toInt().toFloat() == value) {
        value.toInt().toString()
    } else {
        value.toString()
    }
}