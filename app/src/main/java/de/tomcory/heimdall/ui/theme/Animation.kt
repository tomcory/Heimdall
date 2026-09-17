package de.tomcory.heimdall.ui.theme

import androidx.compose.animation.core.Easing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.SpringSpec
import androidx.compose.animation.core.TweenSpec
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween

/**
 * Heimdall animation system — three tiers:
 *
 * Tier 1 — Functional: every state change that would otherwise feel jarring.
 *           Use for button states, filter application, content swaps.
 *
 * Tier 2 — Data-driven: live data elements that reflect system state.
 *           Use for counters ticking up, chart lines drawing in, timers updating.
 *
 * Tier 3 — Expressive: reserved for high-impact transitions.
 *           Use for the risk ring fill, row expand-to-card, VPN activation.
 */
object HeimdallAnimation {

    // ── Tier 1: Functional ────────────────────────────────────────────────────

    fun <T> tier1(): TweenSpec<T> = tween(
        durationMillis = 200,
        easing = FastOutSlowInEasing,
    )

    val tier1DurationMillis = 200

    // ── Tier 2: Data-driven ───────────────────────────────────────────────────

    fun <T> tier2(durationMillis: Int = 300): TweenSpec<T> = tween(
        durationMillis = durationMillis,
        easing = FastOutSlowInEasing,
    )

    val tier2DurationMillis = 300

    // ── Tier 3: Expressive ────────────────────────────────────────────────────

    fun <T> tier3(): SpringSpec<T> = spring(
        dampingRatio = 0.7f,
        stiffness = Spring.StiffnessMedium,
    )

    // Slightly bouncier variant for hero elements (risk ring fill)
    fun <T> tier3Hero(): SpringSpec<T> = spring(
        dampingRatio = 0.65f,
        stiffness = Spring.StiffnessLow,
    )

    // Standard screen-enter fade — used when navigating between tabs
    fun <T> screenEnter(): TweenSpec<T> = tween(
        durationMillis = 300,
        easing = FastOutSlowInEasing,
    )
}
