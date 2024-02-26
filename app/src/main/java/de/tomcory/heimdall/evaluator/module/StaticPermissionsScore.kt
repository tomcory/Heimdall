package de.tomcory.heimdall.evaluator.module

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.Report
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.core.database.entity.SubReport
import de.tomcory.heimdall.evaluator.ModuleResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import org.json.JSONObject
import timber.log.Timber

/**
 * Module that evaluates the static, potentially requested permission of apps.
 */
class StaticPermissionsScore(
    database: HeimdallDatabase
) : Module(
    database = database
) {
    override val name: String = "StaticPermissionScore"
    val label: String = "Permissions"

    @RequiresApi(Build.VERSION_CODES.P)
    override suspend fun calculateOrLoad(
        app: App,
        context: Context,
        forceRecalculate: Boolean
    ): Result<ModuleResult> {

        // load permissions from database
        val permissions = database.appXPermissionDao().getAppWithPermissions(app.packageName).permissions
        val permissionCountInfo = PermissionCountInfo(
            dangerousPermissionCount = permissions.count { it.dangerous },
            signaturePermissionCount = 0, //TODO: implement signature permission count
            normalPermissionCount = permissions.count { !it.dangerous }
        )

        // compute score - point subtraction for different types of permission is chosen arbitrarily
        val score = maxOf(1f -
                permissionCountInfo.dangerousPermissionCount * 0.4f -
                permissionCountInfo.signaturePermissionCount * 0.02f -
                permissionCountInfo.normalPermissionCount * 0.01f,
            0f
        )

        // parse permission counts into json for storing in db
        val details = Json.encodeToString(permissionCountInfo)

        // return success result with module results, containing name, score and details
        return Result.success(ModuleResult(this.name, score, additionalDetails = details))
    }

    @Composable
    override fun BuildUICard(report: ReportWithSubReports?) {
        // calling template UI Card builder
        super.UICard(
            title = this.label,
            infoText = "This modules inspects the permissions the app might request at some point. These are categorized into 'Dangerous', 'Signature' and 'Normal'"
        ) {
            // display own content in card
            UICardContent(report)
        }
    }

    /**
     * Given a [report], this loads and returns the [SubReport] issued by this module for the specific report from the database.
     * TODO: consider storing of report history. The are potentially multiple SubReports. Should consider using [Report.reportId].
     */
    private fun loadSubReportFromDB(report: Report): SubReport? {
        return database.subReportDao().getSubReportsByPackageNameAndModule(
            report.appPackageName,
            name
        )
    }

    /**
     * decode json details [info] string back into [PermissionCountInfo].
     */
    private fun decode(info: String): PermissionCountInfo? {
        Timber.d("trying to decode: $info")

        return try {
            Json.decodeFromString(info)
        } catch (e: Exception) {
            Timber.w(e, "Failed to decode in module: ${this.name}")
            // return null if decoding failed
            null
        }
    }

    /**
     * loads [SubReport] matching the given [report] from database and decode the [SubReport.additionalDetails] from json to [PermissionCountInfo].
     * Uses [loadSubReportFromDB] and [decode].
     */
    private fun loadAndDecode(report: ReportWithSubReports?): PermissionCountInfo? {
        if(report == null) {
            Timber.w("StaticPermissionsScore: report is null")
            return null
        }
        var permissionCountInfo: PermissionCountInfo? = null
        val subReport: SubReport? = report.subReports.find { it.module == name }
        subReport?.let {
            permissionCountInfo = decode(it.additionalDetails)

        }
        Timber.d("decoded sub-report: $permissionCountInfo")
        return permissionCountInfo
    }


    /**
     * Inner Content of UI card for this module.
     * Visulizes the [PermissionCountInfo] in a [DonutChart].
     */
    @Composable
    fun UICardContent(report: ReportWithSubReports?) {
        var permissionCountInfo: PermissionCountInfo? by remember { mutableStateOf(null) }
        var loadingPermissions by remember { mutableStateOf(true) }

        // load permission info
        LaunchedEffect(key1 = 1) {
            this.launch(Dispatchers.IO) {
                permissionCountInfo = loadAndDecode(report)
                loadingPermissions = false
            }
        }

        // show loading animation
        AnimatedVisibility(visible = loadingPermissions, enter = fadeIn(), exit = fadeOut()) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }

        // when loaded, show content
        AnimatedVisibility(
            visible = !loadingPermissions,
            enter = slideInVertically(),
            exit = slideOutVertically()
        ) {
            Column(
                modifier = Modifier.padding(12.dp, 12.dp)
            ) {
                Spacer(modifier = Modifier.height(8.dp))
                // when permission info is set, display donut chart
                permissionCountInfo?.let {
                    DonutChart(
                        values = listOf(
                            it.dangerousPermissionCount.toFloat(),
                            it.signaturePermissionCount.toFloat(),
                            it.normalPermissionCount.toFloat()
                        ),
                        legend = listOf("Dangerous", "Normal", "Signature"),
                        size = 150.dp,
                        colors = listOf(
                            Color.Red,
                            Color.Yellow,
                            Color.Green
                        )
                    )
                }
            }
            // if no info found, display text
            if (permissionCountInfo == null) {
                // No Permission info found
                Text(text = "No permission information found.")
            }
        }
    }


    override fun exportToJsonObject(subReport: SubReport?): JsonObject {
        // return empty json if subreport is null
        if (subReport == null) return buildJsonObject {
            put(name, JSONObject.NULL as JsonElement)
        }
        // decode subreport
        val permissionInfo: PermissionCountInfo? = decode(subReport.additionalDetails)
        // parse permission info to Json object. This is NOT a string but a Kotlin internal Json handling object
        val permissionInfoJson = Json.encodeToJsonElement(permissionInfo).jsonObject
        // parse subreport to Json object. Similarly NOT a string
        var serializedJsonObject: JsonObject = Json.encodeToJsonElement(subReport).jsonObject
        // remove old permission info string
        serializedJsonObject = JsonObject(serializedJsonObject.minus("additionalDetails"))
        // add permission info json object and return build json subreport
        val additionalPair = Pair("permission info", permissionInfoJson)
        return JsonObject(serializedJsonObject.plus(additionalPair))
    }

    override fun exportToJson(subReport: SubReport?): String {
        // first crafts json objects, then parses to string
        return exportToJsonObject(subReport).toString()
    }
}

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

                var arcRadius = size.toPx() - thickness.toPx()
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

/**
 * Data class for storing the permission counts of an apps.
 */
@Serializable
data class PermissionCountInfo(
    val dangerousPermissionCount: Int,
    val signaturePermissionCount: Int,
    val normalPermissionCount: Int
)
