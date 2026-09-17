package de.tomcory.heimdall.ui.theme

import androidx.compose.ui.graphics.Color

// ── Base palette ───────────────────────────────────────────────────────────────
// Accent: electric teal.  Surfaces: near-black (dark) / cool off-white (light).
// Red/amber/green are reserved for the semantic risk system — never use them here.

// Light mode
val md_theme_light_primary             = Color(0xFF0D9488)  // teal-600
val md_theme_light_onPrimary           = Color(0xFFFFFFFF)
val md_theme_light_primaryContainer    = Color(0xFFCCFBF1)  // teal-100
val md_theme_light_onPrimaryContainer  = Color(0xFF134E4A)  // teal-900

val md_theme_light_secondary           = Color(0xFF3D444D)
val md_theme_light_onSecondary         = Color(0xFFFFFFFF)
val md_theme_light_secondaryContainer  = Color(0xFFD8DEE4)
val md_theme_light_onSecondaryContainer= Color(0xFF1C2128)

val md_theme_light_tertiary            = Color(0xFF57606A)
val md_theme_light_onTertiary          = Color(0xFFFFFFFF)
val md_theme_light_tertiaryContainer   = Color(0xFFE1E5EA)
val md_theme_light_onTertiaryContainer = Color(0xFF1C2128)

val md_theme_light_error               = Color(0xFFBA1A1A)
val md_theme_light_errorContainer      = Color(0xFFFFDAD6)
val md_theme_light_onError             = Color(0xFFFFFFFF)
val md_theme_light_onErrorContainer    = Color(0xFF410002)

val md_theme_light_background          = Color(0xFFF6F8FA)  // cool off-white
val md_theme_light_onBackground        = Color(0xFF1C2128)
val md_theme_light_surface             = Color(0xFFF6F8FA)
val md_theme_light_onSurface           = Color(0xFF1C2128)
val md_theme_light_surfaceVariant      = Color(0xFFE1E5EA)
val md_theme_light_onSurfaceVariant    = Color(0xFF3D444D)
val md_theme_light_outline             = Color(0xFF89929B)
val md_theme_light_inverseOnSurface    = Color(0xFFF6F8FA)
val md_theme_light_inverseSurface      = Color(0xFF1C2128)
val md_theme_light_inversePrimary      = Color(0xFF2DD4BF)  // teal-400
val md_theme_light_surfaceTint         = Color(0xFF0D9488)
val md_theme_light_outlineVariant      = Color(0xFFC8D0D9)
val md_theme_light_scrim               = Color(0xFF000000)

// Dark mode — near-black surfaces inspired by GitHub dark
val md_theme_dark_primary              = Color(0xFF2DD4BF)  // teal-400 — vivid on dark
val md_theme_dark_onPrimary            = Color(0xFF0D2E2C)
val md_theme_dark_primaryContainer     = Color(0xFF134E4A)  // teal-900
val md_theme_dark_onPrimaryContainer   = Color(0xFF99F6E4)  // teal-200

val md_theme_dark_secondary            = Color(0xFF768390)
val md_theme_dark_onSecondary          = Color(0xFF161B22)
val md_theme_dark_secondaryContainer   = Color(0xFF21262D)
val md_theme_dark_onSecondaryContainer = Color(0xFFCDD9E5)

val md_theme_dark_tertiary             = Color(0xFF89929B)
val md_theme_dark_onTertiary           = Color(0xFF0D1117)
val md_theme_dark_tertiaryContainer    = Color(0xFF2D333B)
val md_theme_dark_onTertiaryContainer  = Color(0xFFCDD9E5)

val md_theme_dark_error                = Color(0xFFFFB4AB)
val md_theme_dark_errorContainer       = Color(0xFF93000A)
val md_theme_dark_onError              = Color(0xFF690005)
val md_theme_dark_onErrorContainer     = Color(0xFFFFDAD6)

val md_theme_dark_background           = Color(0xFF0D1117)  // GitHub Primer dark
val md_theme_dark_onBackground         = Color(0xFFCDD9E5)
val md_theme_dark_surface              = Color(0xFF0D1117)
val md_theme_dark_onSurface            = Color(0xFFCDD9E5)
val md_theme_dark_surfaceVariant       = Color(0xFF2D333B)
val md_theme_dark_onSurfaceVariant     = Color(0xFF768390)
val md_theme_dark_outline              = Color(0xFF444C56)
val md_theme_dark_inverseOnSurface     = Color(0xFF0D1117)
val md_theme_dark_inverseSurface       = Color(0xFFCDD9E5)
val md_theme_dark_inversePrimary       = Color(0xFF0D9488)
val md_theme_dark_surfaceTint          = Color(0xFF2DD4BF)
val md_theme_dark_outlineVariant       = Color(0xFF2D333B)
val md_theme_dark_scrim                = Color(0xFF000000)

// ── Semantic risk colors ───────────────────────────────────────────────────────
// Used in risk rings, section headers, tracker badges, stat chips.
// Color = meaning. Never use these for decoration.

val RiskHigh              = Color(0xFFE53935)
val RiskHighContainer     = Color(0xFFFFDAD6)
val OnRiskHighContainer   = Color(0xFF410002)

val RiskMedium            = Color(0xFFFFA726)
val RiskMediumContainer   = Color(0xFFFFEDCC)
val OnRiskMediumContainer = Color(0xFF3B2000)

val RiskLow               = Color(0xFF43A047)
val RiskLowContainer      = Color(0xFFD4EDD5)
val OnRiskLowContainer    = Color(0xFF002108)

val RiskUnknown              = Color(0xFF768390)
val RiskUnknownContainer     = Color(0xFF2D333B)
val OnRiskUnknownContainer   = Color(0xFFCDD9E5)

// Dark-mode risk variants
val RiskHighDark              = Color(0xFFFF6B6B)
val RiskHighContainerDark     = Color(0xFF93000A)
val OnRiskHighContainerDark   = Color(0xFFFFDAD6)

val RiskMediumDark            = Color(0xFFFFB74D)
val RiskMediumContainerDark   = Color(0xFF5C3A00)
val OnRiskMediumContainerDark = Color(0xFFFFEDCC)

val RiskLowDark               = Color(0xFF81C784)
val RiskLowContainerDark      = Color(0xFF1B3E1C)
val OnRiskLowContainerDark    = Color(0xFFD4EDD5)

val RiskUnknownDark              = Color(0xFF89929B)
val RiskUnknownContainerDark     = Color(0xFF21262D)
val OnRiskUnknownContainerDark   = Color(0xFFCDD9E5)
