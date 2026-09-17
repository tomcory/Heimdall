package de.tomcory.heimdall.ui.common

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import de.tomcory.heimdall.ui.theme.HeimdallTheme

@Composable
fun shimmerBrush(
    baseColor: Color = MaterialTheme.colorScheme.surfaceVariant,
    highlightColor: Color = MaterialTheme.colorScheme.surface,
): Brush {
    val transition = rememberInfiniteTransition(label = "shimmer")
    val translateX by transition.animateFloat(
        initialValue = -600f,
        targetValue = 600f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "shimmerTranslate",
    )

    return Brush.linearGradient(
        colors = listOf(baseColor, highlightColor, baseColor),
        start = Offset(translateX, 0f),
        end = Offset(translateX + 600f, 0f),
    )
}

/**
 * A shimmer placeholder box. Use wherever content is loading.
 */
@Composable
fun SkeletonBox(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 8.dp,
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(cornerRadius))
            .background(shimmerBrush()),
    )
}

/** Convenience: full-width skeleton line at a given height. */
@Composable
fun SkeletonLine(
    height: Dp = 16.dp,
    widthFraction: Float = 1f,
    cornerRadius: Dp = 4.dp,
    modifier: Modifier = Modifier,
) {
    SkeletonBox(
        modifier = modifier
            .fillMaxWidth(widthFraction)
            .height(height),
        cornerRadius = cornerRadius,
    )
}

/** Convenience: fixed-size skeleton circle (for app icons, avatars). */
@Composable
fun SkeletonCircle(size: Dp, modifier: Modifier = Modifier) {
    SkeletonBox(
        modifier = modifier
            .width(size)
            .height(size),
        cornerRadius = size / 2,
    )
}

@Preview(showBackground = true)
@Composable
private fun SkeletonPreview() {
    HeimdallTheme {
        Box(modifier = Modifier.background(MaterialTheme.colorScheme.surface)) {
            Spacer(modifier = Modifier.height(8.dp))
            SkeletonLine(height = 20.dp, widthFraction = 0.6f)
        }
    }
}
