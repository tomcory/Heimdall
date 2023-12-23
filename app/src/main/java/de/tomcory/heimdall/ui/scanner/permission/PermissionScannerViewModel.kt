package de.tomcory.heimdall.ui.scanner.permission

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.scanner.PermissionScanner
import de.tomcory.heimdall.ui.scanner.ScannerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

class PermissionScannerViewModel @Inject constructor(
    @SuppressLint("StaticFieldLeak") @ApplicationContext private val context: Context,
    private val repository: ScannerRepository
) : ViewModel() {

    val scanActiveInitial = false
    val scanProgressInitial = 0f
    val lastUpdatedInitial = 0L

    ///////////////////////////////
    // State variables
    ///////////////////////////////

    private val _scanActive = MutableStateFlow(scanActiveInitial)
    val scanActive = _scanActive.asStateFlow()

    private val _scanProgress = MutableStateFlow(scanProgressInitial)
    val scanProgress = _scanProgress.asStateFlow()

    private val _lastUpdated = MutableStateFlow(lastUpdatedInitial)
    val lastUpdated = _lastUpdated.asStateFlow()

    ///////////////////////////////
    // Event handlers
    ///////////////////////////////

    fun onScan(onShowSnackbar: (String) -> Unit) {
        viewModelScope.launch {
            _scanActive.emit(true)

            val scanResult = scanAllApps(context)

            if (scanResult) {
                onShowSnackbar("Scan completed.")
            } else {
                onShowSnackbar("Scan cancelled.")
            }
            _scanActive.emit(false)
        }
    }

    fun onScanCancel() {
        viewModelScope.launch {
            _scanActive.emit(false)
        }
    }

    fun onShowDetails() {
        TODO("Not yet implemented")
    }

    ///////////////////////////////
    // Private methods
    ///////////////////////////////

    private suspend fun scanAllApps(context: Context) : Boolean {

        _scanProgress.emit(0f)

        // fetch necessary preferences
        val scope = repository.preferences.permissionMonitoringScope.first()
        val whitelist = repository.preferences.permissionWhitelist.first()
        val blacklist = repository.preferences.permissionBlacklist.first()

        // create a permission scanner
        val permissionScanner = PermissionScanner()

        _scanProgress.emit(0.03f)

        // get a list of all installed apps
        val pm: PackageManager = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_META_DATA.toLong()))
        } else {
            pm.getInstalledPackages(PackageManager.GET_META_DATA)
        }

        _scanProgress.emit(0.08f)

        // filter the list of apps according to the scope
        val filtered = packages.filter(getScanPredicate(scope, whitelist, blacklist))
        Timber.d("Scanning ${filtered.size} apps in monitoring scope $scope...")

        _scanProgress.emit(0.1f)

        // calculate the progress that each individual app scan contributes
        val progressStep = 0.89f / filtered.size
        var progressValue = 0.1f

        // scan each app
        filtered.forEach {

            // check if the scan has been cancelled
            if (!scanActive.value) {
                return false
            }

            // persist the app in the database
            repository.persistApp(
                App(
                    packageName = it.packageName,
                    label = it.applicationInfo.loadLabel(pm).toString(),
                    versionName = it.versionName ?: "",
                    versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        it.longVersionCode
                    } else {
                        it.versionCode.toLong()
                    },
                    isSystem = it.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                )
            )

            // scan the permissions of the app (also persists them)
            try {
                permissionScanner.scanApp(it)
            } catch (e: Exception) {
                Timber.e(e, "Error scanning permissions of ${it.packageName}")
            }

            // update the progress
            progressValue += progressStep
            _scanProgress.emit(progressValue)
        }

        _scanProgress.emit(1f)
        return true
    }

    private fun getScanPredicate(
        scope: MonitoringScopeApps,
        whitelist: List<String>,
        blacklist: List<String>
    ): (PackageInfo) -> Boolean = when(scope) {

        MonitoringScopeApps.APPS_ALL, MonitoringScopeApps.UNRECOGNIZED -> {
            _ -> true
        }

        MonitoringScopeApps.APPS_NON_SYSTEM -> {
            packageInfo -> packageInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0
        }

        MonitoringScopeApps.APPS_WHITELIST -> {
            packageInfo -> whitelist.contains(packageInfo.packageName)
        }

        MonitoringScopeApps.APPS_BLACKLIST -> {
            packageInfo -> !blacklist.contains(packageInfo.packageName)

        }

        MonitoringScopeApps.APPS_NON_SYSTEM_BLACKLIST -> {
            packageInfo -> packageInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0
                && !blacklist.contains(packageInfo.packageName)
        }
    }
}