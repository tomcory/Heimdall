package de.tomcory.heimdall.evaluator.module

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.core.database.entity.SubReport
import de.tomcory.heimdall.core.database.entity.Tracker
import de.tomcory.heimdall.evaluator.ModuleResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.json.JSONObject
import timber.log.Timber

/**
 * Module evaluating the trackers detected in the code of an app.
 */
class TrackerScore(
    database: HeimdallDatabase
) : Module(
    database = database
) {
    override val name: String = "TrackerScore"
    val label = "Tracker Libraries"

    override suspend fun calculateOrLoad(
        app: App,
        context: Context,
        forceRecalculate: Boolean
    ): Result<ModuleResult> {
        // load trackers from db
        val trackers = database.appXTrackerDao().getAppWithTrackers(app.packageName).trackers

        // deduct 0.2 point per tracker - this is pretty arbitrarily chosen
        val score = maxOf(1f - trackers.size * 0.2f, 0f)
        // encode tracker details to string
        val additionalDetails: String = Json.encodeToString(trackers)
        // return result
        return Result.success(ModuleResult(this.name, score, additionalDetails = additionalDetails))
    }

    @Composable
    override fun BuildUICard(report: ReportWithSubReports?) {
        // calling template UI Card builder
        super.UICard(
            title = this.label,
            infoText = "This modules scans for Libraries in the apps code that are know to relate to tracking and lists them."
        ) {
            // display own content in card
            val context = LocalContext.current
            LibraryUICardContent(report = report, context)
        }
    }

    /**
     * Given a [report], this loads and returns the [SubReport] issued by this module for the specific report from the database.
     * TODO: consider storing of report history. The are potentially multiple SubReports. Should consider using [Report.reportId].
     */
    private fun loadSubReportFromDB(report: Report): SubReport {
        return database.subReportDao().getSubReportsByPackageNameAndModule(
            report.appPackageName,
            name
        )
    }

    /**
     * decode json details [info] string back into a [List] of [Tracker]s.
     */
    private fun decode(info: String): List<Tracker> {
        Timber.d("trying to decode: $info")
        return try {
            Json.decodeFromString(info)
        } catch (e: Exception) {
            Timber.w(e, "Failed to decode in module: ${this.name}")
            // return empty list if decoding failed
            listOf()
        }
    }

    /**
     * loads [SubReport] matching the given [report] from database and decode the [SubReport.additionalDetails] from json to [List] of [Tracker]s.
     * Uses [loadSubReportFromDB] and [decode].
     */
    private fun loadAndDecode(report: ReportWithSubReports?): List<Tracker> {
        if(report == null) {
            Timber.w("TrackerScore: report is null")
            return listOf()
        }
        val subReport: SubReport? = report.subReports.find { it.module == name }
        return subReport?.let {
            decode(it.additionalDetails)
        } ?: listOf()
    }

    /**
     * Inner Content of UI card for this module.
     * Visualizes found [Tracker]s and links to them.
     */
    @Composable
    fun LibraryUICardContent(report: ReportWithSubReports?, context: Context) {
        var trackers: List<Tracker> by remember { mutableStateOf(listOf()) }
        var loadingTrackers by remember { mutableStateOf(true) }

        // load tracker info
        LaunchedEffect(key1 = 2, block = {
            this.launch(Dispatchers.IO) {
                trackers = loadAndDecode(report)
                loadingTrackers = false
            }
        })
        // show loading animation
        AnimatedVisibility(visible = loadingTrackers, enter = fadeIn(), exit = fadeOut()) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }

        // when loaded, show content
        AnimatedVisibility(
            visible = !loadingTrackers,
            enter = slideInVertically(),
            exit = slideOutVertically()
        ) {
            Column {
                // if trackers where found, show List
                if (trackers.isNotEmpty()) {
                    // create entry for each tracker, containing name and url
                    for (tracker in trackers) {
                        ListItem(
                            headlineContent = { Text(text = tracker.name) },
                            supportingContent = { Text(text = tracker.web) },
                            modifier = Modifier.clickable(tracker.web.isNotEmpty()) {
                                // open the tracker's URL in the browser
                                val browserIntent =
                                    Intent(Intent.ACTION_VIEW, Uri.parse(tracker.web))
                                ContextCompat.startActivity(context, browserIntent, null)
                            }
                        )
                    }
                } else {
                    // no trackers found
                    Text(text = "No tracker libraries found")
                }
            }
        }
    }

    override fun exportToJsonObject(subReport: SubReport?): JsonObject {
        // return empty json if subreport is null
        if (subReport == null) return buildJsonObject {
            put(name, JSONObject.NULL as JsonElement)
        }
        // decode subreport
        val trackers =
            Json.encodeToJsonElement(Json.decodeFromString<List<Tracker>>(subReport.additionalDetails)).jsonArray
        // parse tracker list to Json object. This is NOT a string but a Kotlin internal Json handling object
        var serializedJsonObject: JsonObject = Json.encodeToJsonElement(subReport).jsonObject
        // remove old tracker info string
        serializedJsonObject = JsonObject(serializedJsonObject.minus("additionalDetails"))
        // add permission info json object and return build json subreport
        val additionalPair = Pair("trackers", trackers)
        return JsonObject(serializedJsonObject.plus(additionalPair))
    }

    override fun exportToJson(subReport: SubReport?): String {
        // first crafts json objects, then parses to string
        return exportToJsonObject(subReport).toString()
    }
}