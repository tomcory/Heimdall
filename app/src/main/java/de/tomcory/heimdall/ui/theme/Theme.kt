package de.tomcory.heimdall.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

private val lightColors = lightColorScheme(
    primary = md_theme_light_primary,
    onPrimary = md_theme_light_onPrimary,
    primaryContainer = md_theme_light_primaryContainer,
    onPrimaryContainer = md_theme_light_onPrimaryContainer,
    secondary = md_theme_light_secondary,
    onSecondary = md_theme_light_onSecondary,
    secondaryContainer = md_theme_light_secondaryContainer,
    onSecondaryContainer = md_theme_light_onSecondaryContainer,
    tertiary = md_theme_light_tertiary,
    onTertiary = md_theme_light_onTertiary,
    tertiaryContainer = md_theme_light_tertiaryContainer,
    onTertiaryContainer = md_theme_light_onTertiaryContainer,
    error = md_theme_light_error,
    errorContainer = md_theme_light_errorContainer,
    onError = md_theme_light_onError,
    onErrorContainer = md_theme_light_onErrorContainer,
    background = md_theme_light_background,
    onBackground = md_theme_light_onBackground,
    surface = md_theme_light_surface,
    onSurface = md_theme_light_onSurface,
    surfaceVariant = md_theme_light_surfaceVariant,
    onSurfaceVariant = md_theme_light_onSurfaceVariant,
    outline = md_theme_light_outline,
    inverseOnSurface = md_theme_light_inverseOnSurface,
    inverseSurface = md_theme_light_inverseSurface,
    inversePrimary = md_theme_light_inversePrimary,
    surfaceTint = md_theme_light_surfaceTint,
    outlineVariant = md_theme_light_outlineVariant,
    scrim = md_theme_light_scrim,
)

private val darkColors = darkColorScheme(
    primary = md_theme_dark_primary,
    onPrimary = md_theme_dark_onPrimary,
    primaryContainer = md_theme_dark_primaryContainer,
    onPrimaryContainer = md_theme_dark_onPrimaryContainer,
    secondary = md_theme_dark_secondary,
    onSecondary = md_theme_dark_onSecondary,
    secondaryContainer = md_theme_dark_secondaryContainer,
    onSecondaryContainer = md_theme_dark_onSecondaryContainer,
    tertiary = md_theme_dark_tertiary,
    onTertiary = md_theme_dark_onTertiary,
    tertiaryContainer = md_theme_dark_tertiaryContainer,
    onTertiaryContainer = md_theme_dark_onTertiaryContainer,
    error = md_theme_dark_error,
    errorContainer = md_theme_dark_errorContainer,
    onError = md_theme_dark_onError,
    onErrorContainer = md_theme_dark_onErrorContainer,
    background = md_theme_dark_background,
    onBackground = md_theme_dark_onBackground,
    surface = md_theme_dark_surface,
    onSurface = md_theme_dark_onSurface,
    surfaceVariant = md_theme_dark_surfaceVariant,
    onSurfaceVariant = md_theme_dark_onSurfaceVariant,
    outline = md_theme_dark_outline,
    inverseOnSurface = md_theme_dark_inverseOnSurface,
    inverseSurface = md_theme_dark_inverseSurface,
    inversePrimary = md_theme_dark_inversePrimary,
    surfaceTint = md_theme_dark_surfaceTint,
    outlineVariant = md_theme_dark_outlineVariant,
    scrim = md_theme_dark_scrim,
)

// ── Semantic risk color bundle ────────────────────────────────────────────────

@Immutable
data class RiskColors(
    val high: Color,
    val highContainer: Color,
    val onHighContainer: Color,
    val medium: Color,
    val mediumContainer: Color,
    val onMediumContainer: Color,
    val low: Color,
    val lowContainer: Color,
    val onLowContainer: Color,
    val unknown: Color,
    val unknownContainer: Color,
    val onUnknownContainer: Color,
)

private val lightRiskColors = RiskColors(
    high = RiskHigh,
    highContainer = RiskHighContainer,
    onHighContainer = OnRiskHighContainer,
    medium = RiskMedium,
    mediumContainer = RiskMediumContainer,
    onMediumContainer = OnRiskMediumContainer,
    low = RiskLow,
    lowContainer = RiskLowContainer,
    onLowContainer = OnRiskLowContainer,
    unknown = RiskUnknown,
    unknownContainer = RiskUnknownContainer,
    onUnknownContainer = OnRiskUnknownContainer,
)

private val darkRiskColors = RiskColors(
    high = RiskHighDark,
    highContainer = RiskHighContainerDark,
    onHighContainer = OnRiskHighContainerDark,
    medium = RiskMediumDark,
    mediumContainer = RiskMediumContainerDark,
    onMediumContainer = OnRiskMediumContainerDark,
    low = RiskLowDark,
    lowContainer = RiskLowContainerDark,
    onLowContainer = OnRiskLowContainerDark,
    unknown = RiskUnknownDark,
    unknownContainer = RiskUnknownContainerDark,
    onUnknownContainer = OnRiskUnknownContainerDark,
)

val LocalRiskColors = staticCompositionLocalOf { lightRiskColors }

// Convenience accessor — use MaterialTheme.riskColors in composables
val MaterialTheme.riskColors: RiskColors
    @Composable get() = LocalRiskColors.current

@Composable
fun HeimdallTheme(
    useDarkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (useDarkTheme) darkColors else lightColors
    val riskColors = if (useDarkTheme) darkRiskColors else lightRiskColors

    CompositionLocalProvider(LocalRiskColors provides riskColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = HeimdallTypography,
            content = content,
        )
    }
}
