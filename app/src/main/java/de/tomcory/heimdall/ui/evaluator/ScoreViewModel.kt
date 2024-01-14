package de.tomcory.heimdall.ui.evaluator

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager.NameNotFoundException
import android.graphics.drawable.Drawable
import android.net.Uri
import androidx.core.content.ContextCompat
import androidx.core.content.ContextCompat.startActivity
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.AppWithReportsAndSubReports
import de.tomcory.heimdall.core.database.entity.ReportWithSubReports
import de.tomcory.heimdall.evaluator.Evaluator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject

/**
 * ViewModel for the [AppScoreScreen] Composable.
 * Holds the UI State and performance heavy operations.
 */
@HiltViewModel
class ScoreViewModel @Inject constructor (
    private val database: HeimdallDatabase,
    private val evaluator: Evaluator,
    @SuppressLint("StaticFieldLeak") @ApplicationContext private val context: Context
) : ViewModel() {

    val evaluatorModules = evaluator.modules

    // flow of apps from the database
    val apps: Flow<List<AppWithReportsAndSubReports>> = database.reportDao().getAllAppsWithReportsAndSubReports()

    // cached app icons
    private val appIcons: MutableMap<String, Drawable> = mutableMapOf()

    // state variables

    private val _loading = MutableStateFlow(true)
    val loading: StateFlow<Boolean> = _loading.asStateFlow()

    // state for selected app
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

    /**
     * Get the cached icon for the app with [packageName] or load it from the system if not cached yet.
     * Returns the default icon if the app is not installed.
     */
    suspend fun getAppIcon(packageName: String): Drawable {
        return withContext(Dispatchers.IO) {
            appIcons[packageName]
                ?: try {
                    context.packageManager.getApplicationIcon(packageName).also {
                        appIcons[packageName] = it
                    }
                } catch (e: NameNotFoundException) {
                    // default icon
                    //TODO: replace with custom icon
                    ContextCompat.getDrawable(context, android.R.drawable.sym_def_app_icon)!!
                }
        }
    }

    suspend fun selectApp(app: AppWithReportsAndSubReports) {
        _selectedAppPackageName.value = app.app.packageName
        _selectedAppPackageLabel.value = app.app.label
        _selectedAppPackageIcon.value = getAppIcon(app.app.packageName)
        _selectedAppReports.value = app.reports
        _selectedAppLatestReport.value = app.reports.firstOrNull()
    }

    /**
     * Scan currently selected app and expose the new report to the UI. Calls [scoreApp].
     */
    suspend fun scoreSelectedApp() {
        withContext(Dispatchers.IO) {
            // trigger rescan
            val report = scoreApp(selectedAppPackageName.value)
            if (report != null) {
                // update state - does nothing if report remains unchanged
                _selectedAppLatestReport.update { report }
                Timber.d("Updated UI with new report")
            } else {
                Timber.d("No new report")
            }
        }
    }

    /**
     * Scan app with [packageName] and return the new report.
     * Returns null if no new report was generated due to an error.
     */
    suspend fun scoreApp(packageName: String): ReportWithSubReports? {
        return withContext(Dispatchers.IO) {
            Timber.d("Scoring $packageName...")
            evaluator.evaluateApp(packageName, context)
        }
    }

    /**
     * Scan all apps. Calls [scoreApp] for each app.
     */
    suspend fun scoreAllApps() {
        withContext(Dispatchers.IO) {
            apps.first().forEach { app ->
                scoreApp(app.app.packageName)
            }
        }
    }

    /**
     *  Triggers operating system uninstall flow for the current app.
     */
    fun uninstallApp(composableContext: Context) {
        val uri: Uri = Uri.fromParts("package", selectedAppPackageName.value, null)
        val uninstallIntent = Intent(Intent.ACTION_DELETE, uri)

        startActivity(composableContext, uninstallIntent, null)
    }

    /**
     *  trigger export of report for the current app
     */
    suspend fun exportToJson() {
        withContext(Dispatchers.IO) {
            val json = evaluator.exportReportToJson(selectedAppLatestReport.value)

            val sendIntent: Intent = Intent().apply {
                action = Intent.ACTION_SEND
                putExtra(Intent.EXTRA_TEXT, json)
                type = "text/json"
            }

            val shareIntent = Intent.createChooser(sendIntent, null)
            startActivity(context, shareIntent, null)
        }
    }
}