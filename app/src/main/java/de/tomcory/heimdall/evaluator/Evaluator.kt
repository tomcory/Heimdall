package de.tomcory.heimdall.evaluator

import android.content.Context
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.core.database.entity.SubReport
import de.tomcory.heimdall.evaluator.module.Module
import de.tomcory.heimdall.evaluator.module.PrivacyPolicyScore
import de.tomcory.heimdall.evaluator.module.StaticPermissionsScore
import de.tomcory.heimdall.evaluator.module.TrackerScore
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import org.json.JSONObject
import timber.log.Timber
import javax.inject.Inject

/**
 * Evaluator Service responsible for all app evaluation, scoring, creating and storing reports and module specific UI elements.
 * Abstraction interface between modules and application.
 *
 * @constructor should not be manually constructed, use Hilt dependency injection instead.
 */
class Evaluator @Inject constructor(
    val database: HeimdallDatabase
) {

    /**
     * List of [Module]s known to the evaluator. Only modules included here are considered in evaluation.
     */
    val modules: List<Module> = listOf(
        StaticPermissionsScore(database),
        TrackerScore(database),
        PrivacyPolicyScore(database)
    )

    /**
     * Main action of [Evaluator].
     * Evaluates an app by [packageName] trough calling all registered [modules] to evaluate the app.
     * Resulting scores are collected and calculates average as main Score.
     * Creates and stores a [Report] with this score and additional metadata in the database.
     *
     * Currently, only weights set in Modules are respected.
     *
     * Suspends for fetching app info from database.
     * [context] may be used for computation, e.g. calling package manager.
     *
     * Returns the created [Report] and associated [SubReport]s
     *
     * @see Report
     */
    suspend fun evaluateApp(packageName: String, context: Context): ReportWithSubReports? {

        // fetching app info from db
        val app = database.appDao().getAppByPackageName(packageName)

        // break if no info found
        if (app == null) {
            Timber.d("Evaluation of $packageName failed, because Database Entry not found")
            return null
        }

        Timber.d("Evaluating score of $packageName")

        val results = mutableListOf<ModuleResult>()

        // count of valid module responses. Might be reduced during loop - needed to calculate average
        var validResponses = modules.size

        // looping trough and requesting evaluation
        for (module in modules) {

            // Result of current module
            val result = module.calculateOrLoad(app, context)

            // case: Result failure - no valid result
            if (result.isFailure) {
                // logging failure
                Timber.w(
                    result.exceptionOrNull(),
                    "Module $module encountered Error while evaluating $app"
                )
                // reducing count for average computation
                validResponses--
                continue
            }
            // case: Result success - valid response
            else {
                // should not be necessary to call safe getOrNull but compiler complained
                result.getOrNull()?.let {

                    // add to result collection
                    results.add(it)

                    // logging
                    Timber.d("module $module result: ${it.score}")
                }
            }
        }
        // check if result scores are in range 0..1
        if (results.any { it.score > 1f || it.score < 0f }) {
            Timber.w("some module result scores are not in range 0..1")
        }
        // compute average score, respecting (default) weights of modules
        val totalScore = results.fold(0.0) { sum, s -> sum + s.score * s.weight } / validResponses
        // logging
        Timber.d("evaluation complete for ${app.packageName}: $totalScore}")
        // creating Report and storing database
        return createReport(app.packageName, totalScore, results)
    }

    /**
     * Creates a [Report] for the app containing [packageName] and [totalScore] and transforms [ModuleResult] to [SubReport], adding metadata like current time as timestamp.
     * If successful, storing both in database
     *
     * Returns  Pair of the created Report and transformed SubReports
     */
    private suspend fun createReport(
        packageName: String,
        totalScore: Double,
        moduleResults: MutableList<ModuleResult>
    ): ReportWithSubReports {
        // logging
        Timber.d("writing Report and SubReports to Database")

        // creating Report with current time as timestamp
        val report = Report(
            appPackageName = packageName,
            timestamp = System.currentTimeMillis(),
            mainScore = totalScore
        )

        // storing report in database
        database.reportDao().insertReport(report).let { reportId ->
            // if successful, create SubReport for each ModuleResult
            val subReports = moduleResults.map() { result ->
                SubReport(
                    reportId = reportId,
                    packageName = packageName,
                    module = result.moduleName,
                    score = result.score,
                    timestamp = result.timestamp,
                    additionalDetails = result.additionalDetails
                )
            }
            // bulk store in database
            database.subReportDao().insertSubReport(subReports)
            return ReportWithSubReports(report, subReports)
        }
    }

    // TODO export to file
    /**
     * Export [report] to json, fetching corresponding [SubReport]s and issue parsing by each module.
     * Currently only exporting JSON to log.
     *
     * @see kotlinx.serialization.json
     * @return report with supports as json encoded string
     */
    fun exportReportToJson(report: ReportWithSubReports?): String {
        // return empty JSON if report is null
        if (report == null) return JSONObject.NULL.toString()

        // fetch corresponding sub-reports from db and issue encoding for each module
        val subReports: List<JsonElement> = report.subReports.map {
            Json.encodeToJsonElement(it)
        }
        // create JSON array from list
        val subReportList = JsonArray(subReports)
        // report to JSONObject
        var serializedReport: JsonObject = Json.encodeToJsonElement(report) as JsonObject
        // appending subreports list to JSON Report
        serializedReport = JsonObject(serializedReport.plus(Pair("subReports", subReportList)))
        // logging
        Timber.d("exported report $report\nto JSON:\n$serializedReport")
        // return JSON report as String
        return serializedReport.toString()
    }
}