package de.tomcory.heimdall.ui.evaluator

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager.NameNotFoundException
import android.graphics.drawable.Drawable
import android.net.Uri
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.AppWithReportsAndSubReports
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.evaluator.Evaluator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject

enum class ScoreFilter { NONE, TRACKERS, DANGEROUS_PERMS }

data class DeviceStats(
    val totalApps: Int = 0,
    val highRiskCount: Int = 0,
    val mediumRiskCount: Int = 0,
    val lowRiskCount: Int = 0,
    val unknownCount: Int = 0,
    val appsWithTrackers: Int = 0,
    val appsWithDangerousPerms: Int = 0,
    val lastScannedTimestamp: Long? = null,
)

@HiltViewModel
class ScoreViewModel @Inject constructor(
    private val database: HeimdallDatabase,
    private val evaluator: Evaluator,
    @field:SuppressLint("StaticFieldLeak") @param:ApplicationContext private val context: Context,
) : ViewModel() {

    val evaluatorModules = evaluator.modules

    private val allApps: Flow<List<AppWithReportsAndSubReports>> =
        database.reportDao().getAllAppsWithReportsAndSubReports()

    private val _activeFilter = MutableStateFlow(ScoreFilter.NONE)
    val activeFilter: StateFlow<ScoreFilter> = _activeFilter.asStateFlow()

    val apps: StateFlow<List<AppWithReportsAndSubReports>> =
        combine(allApps, _activeFilter) { apps, filter ->
            when (filter) {
                ScoreFilter.NONE -> apps
                ScoreFilter.TRACKERS -> apps.filter { app ->
                    app.getLatestReport()?.subReports
                        ?.any { it.module == "TrackerScore" && it.score < 1f } == true
                }
                ScoreFilter.DANGEROUS_PERMS -> apps.filter { app ->
                    app.getLatestReport()?.subReports
                        ?.any { it.module == "StaticPermissionScore" && it.score < 1f } == true
                }
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val deviceStats: StateFlow<DeviceStats> = allApps.map { appList ->
        var high = 0; var medium = 0; var low = 0; var unknown = 0
        var withTrackers = 0; var withDangerousPerms = 0
        var latestTimestamp: Long? = null

        appList.forEach { app ->
            val report = app.getLatestReport()
            val score = report?.report?.mainScore
            when (score.toRiskLevel()) {
                RiskLevel.HIGH    -> high++
                RiskLevel.MEDIUM  -> medium++
                RiskLevel.LOW     -> low++
                RiskLevel.UNKNOWN -> unknown++
            }
            report?.subReports?.forEach { sub ->
                if (sub.module == "TrackerScore" && sub.score < 1f) withTrackers++
                if (sub.module == "StaticPermissionScore" && sub.score < 1f) withDangerousPerms++
            }
            val ts = report?.report?.timestamp
            if (ts != null && (latestTimestamp == null || ts > latestTimestamp!!)) {
                latestTimestamp = ts
            }
        }

        DeviceStats(
            totalApps = appList.size,
            highRiskCount = high,
            mediumRiskCount = medium,
            lowRiskCount = low,
            unknownCount = unknown,
            appsWithTrackers = withTrackers,
            appsWithDangerousPerms = withDangerousPerms,
            lastScannedTimestamp = latestTimestamp,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DeviceStats())

    fun setFilter(filter: ScoreFilter) {
        _activeFilter.value = if (_activeFilter.value == filter) ScoreFilter.NONE else filter
    }

    // ── App icon cache ─────────────────────────────────────────────────────────

    private val appIcons: MutableMap<String, Drawable> = mutableMapOf()

    suspend fun getAppIcon(packageName: String): Drawable {
        return withContext(Dispatchers.IO) {
            appIcons[packageName] ?: try {
                context.packageManager.getApplicationIcon(packageName).also {
                    appIcons[packageName] = it
                }
            } catch (e: NameNotFoundException) {
                ContextCompat.getDrawable(context, android.R.drawable.sym_def_app_icon)!!
            }
        }
    }

    // ── Selected app state ─────────────────────────────────────────────────────

    private val _selectedAppPackageName = MutableStateFlow("")
    val selectedAppPackageName: StateFlow<String> = _selectedAppPackageName.asStateFlow()

    private val _selectedAppPackageLabel = MutableStateFlow("")
    val selectedAppPackageLabel: StateFlow<String> = _selectedAppPackageLabel.asStateFlow()

    private val _selectedAppPackageIcon: MutableStateFlow<Drawable?> = MutableStateFlow(null)
    val selectedAppPackageIcon: StateFlow<Drawable?> = _selectedAppPackageIcon.asStateFlow()

    private val _selectedAppReports = MutableStateFlow(listOf<ReportWithSubReports>())
    val selectedAppReports: StateFlow<List<ReportWithSubReports>> = _selectedAppReports.asStateFlow()

    private val _selectedAppLatestReport: MutableStateFlow<ReportWithSubReports?> = MutableStateFlow(null)
    val selectedAppLatestReport: StateFlow<ReportWithSubReports?> = _selectedAppLatestReport.asStateFlow()

    suspend fun selectApp(app: AppWithReportsAndSubReports) {
        _selectedAppPackageName.value = app.app.packageName
        _selectedAppPackageLabel.value = app.app.label
        _selectedAppPackageIcon.value = getAppIcon(app.app.packageName)
        _selectedAppReports.value = app.reports
        _selectedAppLatestReport.value = app.reports.firstOrNull()
    }

    // ── Scoring actions ────────────────────────────────────────────────────────

    suspend fun scoreSelectedApp() {
        withContext(Dispatchers.IO) {
            val report = scoreApp(selectedAppPackageName.value)
            if (report != null) _selectedAppLatestReport.update { report }
        }
    }

    suspend fun scoreApp(packageName: String): ReportWithSubReports? {
        return withContext(Dispatchers.IO) {
            Timber.d("Scoring $packageName...")
            evaluator.evaluateApp(packageName, context)
        }
    }

    suspend fun scoreAllApps() {
        withContext(Dispatchers.IO) {
            allApps.first().forEach { app -> scoreApp(app.app.packageName) }
        }
    }

    fun uninstallApp(composableContext: Context) {
        val uri = Uri.fromParts("package", selectedAppPackageName.value, null)
        composableContext.startActivity(Intent(Intent.ACTION_DELETE, uri), null)
    }

    suspend fun exportToJson() {
        withContext(Dispatchers.IO) {
            val json = evaluator.exportReportToJson(selectedAppLatestReport.value)
            val shareIntent = Intent.createChooser(
                Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, json)
                    type = "text/json"
                }, null
            )
            context.startActivity(shareIntent, null)
        }
    }
}
