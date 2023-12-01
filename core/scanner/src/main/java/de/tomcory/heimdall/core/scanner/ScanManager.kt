package de.tomcory.heimdall.core.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PackageManager.NameNotFoundException
import android.graphics.drawable.Drawable
import android.os.Build
import de.tomcory.heimdall.MonitoringScopeApps
import de.tomcory.heimdall.MonitoringScopeApps.*
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import timber.log.Timber
import javax.inject.Inject

class ScanManager private constructor(
    private val permissionScanner: PermissionScanner,
    private val libraryScanner: LibraryScanner?
) {
    @Inject
    lateinit var preferences: PreferencesDataSource
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

        val scope = preferences.permissionMonitoringScope.first()

        if(!getScanPredicate(scope)(packageInfo)) {
            Timber.w("App $packageName is not in scan scope $scope")
            return
        }

        val app = App(
            packageName = packageName,
            label = packageInfo.applicationInfo.loadLabel(pm).toString(),
            versionName = packageInfo.versionName,
            versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) packageInfo.longVersionCode else packageInfo.versionCode.toLong(),
            isSystem = packageInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
        )

        HeimdallDatabase.instance?.appDao?.insertApps(app)

        if(preferences.permissionOnInstall.first()) {
            permissionScanner.scanApp(packageInfo)
        }
        if(preferences.libraryOnInstall.first()) {
            libraryScanner?.scanApp(packageInfo)
        }
    }

    suspend fun scanAllApps(context: Context, progress: MutableStateFlow<Float>? = null) {

        progress?.emit(0.01f)

        val pm: PackageManager = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_META_DATA.toLong()))
        } else {
            pm.getInstalledPackages(PackageManager.GET_META_DATA)
        }

        progress?.emit(0.05f)

        val scope = preferences.permissionMonitoringScope.first()

        Timber.d("Scanning apps in scope $scope...")

        val filtered = packages.filter(getScanPredicate(scope))

        val apps = filtered.map {
            App(
                packageName = it.packageName,
                label = it.applicationInfo.loadLabel(pm).toString(),
                versionName = it.versionName ?: "",
                versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) it.longVersionCode else it.versionCode.toLong(),
                isSystem = it.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
            )
        }

        progress?.emit(0.1f)

        Timber.d("Found ${apps.size} apps.")

        HeimdallDatabase.instance?.appDao?.insertApps(*apps.toTypedArray())

        val progressStep = 0.89f / filtered.size
        var progressValue = 0.1f

        filtered.forEach {
            if(preferences.permissionOnInstall.first()) {
                try {
                    permissionScanner.scanApp(it)
                } catch (e: Exception) {
                    Timber.e(e, "Error scanning permissions of ${it.packageName}")
                }

            }
            if(preferences.libraryOnInstall.first()) {
                try {
                    libraryScanner?.scanApp(it)
                } catch (e: Exception) {
                    Timber.e(e, "Error scanning dex classes of ${it.packageName}")
                }
            }

            progressValue += progressStep
            progress?.emit(progressValue)
        }

        progress?.emit(1f)
    }

    private fun getScanPredicate(scope: MonitoringScopeApps): (PackageInfo) -> Boolean = when(scope) {
        APPS_ALL -> { _ -> true }
        APPS_NON_SYSTEM -> { packageInfo -> packageInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0 }
        APPS_WHITELIST -> { _ -> true } //TODO
        APPS_BLACKLIST -> { _ -> true } //TODO
        UNRECOGNIZED -> { _ -> true }
        APPS_NON_SYSTEM_BLACKLIST -> TODO()
    }

    companion object {
        suspend fun create(context: Context): ScanManager = TODO()

//            return ScanManager(
//                permissionScanner = PermissionScanner(),
//                libraryScanner = LibraryScanner.create(
//                    context.preferencesStore.data.first().libraryPrepopulate
//                )
//            )


        fun getAppIcon(context: Context, packageName: String): Drawable {
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
                Timber.e("App $packageName not found, cannot get its icon")
                return pm.defaultActivityIcon
            }

            return packageInfo.applicationInfo.loadIcon(pm)
        }
    }
}