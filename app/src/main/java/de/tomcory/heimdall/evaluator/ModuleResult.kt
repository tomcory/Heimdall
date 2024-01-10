package de.tomcory.heimdall.evaluator

/**
 * Data class representing a evaluation result from a metric module.
 * Only used for exchange from Module to [Evaluator].
 * For further processing, this information should be transformed into SubReport.
 *
 * [score] is expected in range 0..1 and is later factored with [weight].
 *
 * Module specific information can be stored as String (json recommended) in [additionalDetails].
 */
data class ModuleResult(
    val moduleName: String,
    val score: Float,
    val weight: Double = 1.0,
    val additionalDetails: String = "",
    val timestamp: Long = System.currentTimeMillis()
)