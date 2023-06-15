package de.tomcory.heimdall.scanner.code

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PackageManager.NameNotFoundException
import android.os.Build
import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeApps.*
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.persistence.database.entity.App
import de.tomcory.heimdall.ui.main.preferencesStore
import kotlinx.coroutines.flow.first
import timber.log.Timber

class ScanManager private constructor(
    private val permissionScanner: PermissionScanner,
    private val libraryScanner: LibraryScanner?
) {
    suspend fun scanApp(context: Context, packageName: String) {
        Timber.d("Collecting app info of $packageName")

        val pm: PackageManager = context.packageManager

        val packageInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of((PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS).toLong())
                )
            } else {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS
                )
            }
        } catch (e: NameNotFoundException) {
            Timber.e("App $packageName not found, cannot scan it")
            return
        }

        val dataStore = context.preferencesStore.data.first()
        val scope = dataStore.scanMonitoringScope

        if(!getScanPredicate(scope)(packageInfo)) {
            Timber.w("App $packageName is not in scan scope $scope")
            return
        }

        val app = App(
            packageName = packageName,
            label = packageInfo.applicationInfo.loadLabel(pm).toString(),
            versionName = packageInfo.versionName,
            versionCode = packageInfo.longVersionCode
        )

        HeimdallDatabase.instance?.appDao?.insertApps(app)

        if(dataStore.scanPermissionScannerEnable) {
            permissionScanner.scanApp(packageInfo)
        }
        if(dataStore.scanLibraryScannerEnable) {
            libraryScanner?.scanApp(packageInfo)
        }
    }

    suspend fun scanAllApps(context: Context) {
        val pm: PackageManager = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_META_DATA.toLong()))
        } else {
            pm.getInstalledPackages(PackageManager.GET_META_DATA)
        }

        val dataStore = context.preferencesStore.data.first()
        val scope = dataStore.scanMonitoringScope

        Timber.d("Scanning apps in scope $scope...")

        val filtered = packages.filter(getScanPredicate(scope))

        val apps = filtered.map {
            App(
                packageName = it.packageName,
                label = it.applicationInfo.loadLabel(pm).toString(),
                versionName = it.versionName ?: "",
                versionCode = it.longVersionCode
            )
        }

        Timber.d("Found ${apps.size} apps.")

        HeimdallDatabase.instance?.appDao?.insertApps(*apps.toTypedArray())

        filtered.forEach {
            if(dataStore.scanPermissionScannerEnable) {
                try {
                    permissionScanner.scanApp(it)
                } catch (e: Exception) {
                    Timber.e(e, "Error scanning permissions of ${it.packageName}")
                }

            }
            if(dataStore.scanLibraryScannerEnable) {
                try {
                    libraryScanner?.scanApp(it)
                } catch (e: Exception) {
                    Timber.e(e, "Error scanning dex classes of ${it.packageName}")
                }
            }
        }
    }

    private fun getScanPredicate(scope: MonitoringScopeApps): (PackageInfo) -> Boolean = when(scope) {
        APPS_ALL -> { _ -> true }
        APPS_NON_SYSTEM -> { packageInfo -> packageInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0 }
        APPS_WHITELIST -> { _ -> true } //TODO
        APPS_BLACKLIST -> { _ -> true } //TODO
        UNRECOGNIZED -> { _ -> true }
    }

    companion object {
        suspend fun create(context: Context): ScanManager {
            return ScanManager(
                permissionScanner = PermissionScanner(),
                libraryScanner = LibraryScanner.create(
                    context.preferencesStore.data.first().scanLibraryScannerPrepopulate
                )
            )
        }
    }
}