package de.tomcory.heimdall.ui.evaluator

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import de.tomcory.heimdall.ui.theme.RiskColors
import de.tomcory.heimdall.ui.theme.riskColors
import androidx.compose.material3.MaterialTheme

enum class RiskLevel { HIGH, MEDIUM, LOW, UNKNOWN }

fun Double?.toRiskLevel(): RiskLevel = when {
    this == null -> RiskLevel.UNKNOWN
    this < 0.4   -> RiskLevel.HIGH
    this < 0.75  -> RiskLevel.MEDIUM
    else         -> RiskLevel.LOW
}

@Composable
fun RiskLevel.color(): Color {
    val rc = MaterialTheme.riskColors
    return when (this) {
        RiskLevel.HIGH    -> rc.high
        RiskLevel.MEDIUM  -> rc.medium
        RiskLevel.LOW     -> rc.low
        RiskLevel.UNKNOWN -> rc.unknown
    }
}

@Composable
fun RiskLevel.containerColor(): Color {
    val rc = MaterialTheme.riskColors
    return when (this) {
        RiskLevel.HIGH    -> rc.highContainer
        RiskLevel.MEDIUM  -> rc.mediumContainer
        RiskLevel.LOW     -> rc.lowContainer
        RiskLevel.UNKNOWN -> rc.unknownContainer
    }
}

@Composable
fun RiskLevel.onContainerColor(): Color {
    val rc = MaterialTheme.riskColors
    return when (this) {
        RiskLevel.HIGH    -> rc.onHighContainer
        RiskLevel.MEDIUM  -> rc.onMediumContainer
        RiskLevel.LOW     -> rc.onLowContainer
        RiskLevel.UNKNOWN -> rc.onUnknownContainer
    }
}

fun RiskLevel.label(): String = when (this) {
    RiskLevel.HIGH    -> "High Risk"
    RiskLevel.MEDIUM  -> "Medium Risk"
    RiskLevel.LOW     -> "Low Risk"
    RiskLevel.UNKNOWN -> "Unknown"
}
