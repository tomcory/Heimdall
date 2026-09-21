package de.tomcory.heimdall.service

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import androidx.core.content.pm.PackageInfoCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.core.scanner.LibraryScanner
import de.tomcory.heimdall.core.scanner.PermissionScanner
import timber.log.Timber
import java.util.UUID

/**
 * Performs a one‑shot scan of all installed apps after boot or package changes.
 * This replaces the deprecated JobIntentService implementation and fully complies
 * with Android 15 restrictions (no foreground service at boot).
 */
class ScanWorker(
    private val context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    @EntryPoint
    @InstallIn(SingletonComponent::class)
    interface ScanWorkerEntryPoint {
        fun database(): HeimdallDatabase
        fun preferences(): PreferencesDataSource
        fun permissionScanner(): PermissionScanner
        fun libraryScanner(): LibraryScanner
    }

    private val entryPoint by lazy {
        EntryPointAccessors.fromApplication(
            context,
            ScanWorkerEntryPoint::class.java
        )
    }

    private val database by lazy { entryPoint.database() }
    private val permissionScanner by lazy { entryPoint.permissionScanner() }
    private val libraryScanner by lazy { entryPoint.libraryScanner() }

    /**
     * Main worker execution method that handles scanning tasks.
     * Retrieves the optional packageName parameter and either performs
     * a scan of a specific package or a full scan of all installed packages.
     *
     * @return Result indicating success or failure of the worker task
     */
    override suspend fun doWork(): Result {
        return try {
            val packageName = inputData.getString(KEY_PACKAGE_NAME) ?: ""
            val scanLibraries = inputData.getBoolean(KEY_SCAN_LIBRARIES, true)
            val scanPermissions = inputData.getBoolean(KEY_SCAN_PERMISSIONS, true)

            if (packageName.isNotEmpty()) {
                scanSinglePackage(packageName, scanLibraries, scanPermissions)
            } else {
                performFullScan(scanLibraries, scanPermissions)
            }

            Result.success()
        } catch (t: Throwable) {
            Timber.e(t, "Initial scan failed")
            Result.failure()
        }
    }

    /**
     * Scans a single app package based on user preferences.
     * Updates the app information in the database and performs permission
     * and/or library scanning if enabled in preferences.
     *
     * @param packageName The package identifier of the app to scan
     */
    private suspend fun scanSinglePackage(packageName: String, scanLibraries: Boolean, scanPermissions: Boolean) {
        val pm = context.packageManager

        val pkgInfo = try {
            context.packageManager.getPackageInfo(packageName, PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS)
        } catch (e: PackageManager.NameNotFoundException) {
            Timber.e(e, "Package $packageName not found")
            return
        }

        val versionCode = PackageInfoCompat.getLongVersionCode(pkgInfo)
        val versionName = pkgInfo.versionName ?: ""

        val label = pkgInfo.applicationInfo?.loadLabel(pm)?.toString() ?: packageName

        // Always update the app entry in database to ensure current data
        database.appDao().insertApps(
            App(
                packageName = packageName,
                label = label,
                versionCode = versionCode,
                versionName = versionName,
                isSystem = ((pkgInfo.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0,
                flags = pkgInfo.applicationInfo?.flags ?: 0
            )
        )

        Timber.d("Scanning $packageName...")
        if (scanPermissions) {
            permissionScanner.scanApp(pkgInfo)
        }
        if (scanLibraries) {
            libraryScanner.scanApp(pkgInfo)
        }
    }

    /**
     * Performs a full scan of all installed packages on the device.
     * Updates app information in the database and performs permission and/or library
     * scanning for new or updated apps based on user preferences.
     * Reports progress during the scan operation.
     */
    private suspend fun performFullScan(scanLibraries: Boolean, scanPermissions: Boolean) {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS)

        // Get all existing apps from database
        val existingApps = database.appDao().getAll().associateBy { it.packageName }
        val seenPackageNames = mutableSetOf<String>()
        val appsToUpsert = mutableListOf<App>()
        val packagesToScan = mutableListOf<PackageInfo>()

        // Pass 1: determine what changed and collect the App rows, but don't scan yet -
        // AppXPermission/AppXTracker now carry a foreign key to App, so every App row must exist
        // before permissionScanner/libraryScanner can insert rows referencing it.
        packages.forEach { pkgInfo ->
            val packageName = pkgInfo.packageName
            seenPackageNames.add(packageName)
            val versionCode = PackageInfoCompat.getLongVersionCode(pkgInfo)
            val versionName = pkgInfo.versionName ?: ""

            // Check if app is new or has a different version
            val existingApp = existingApps[packageName]
            val isAppChanged = existingApp == null ||
                    existingApp.versionCode != versionCode ||
                    existingApp.versionName != versionName ||
                    !existingApp.isInstalled

            val label = pkgInfo.applicationInfo?.loadLabel(pm)?.toString() ?: packageName

            appsToUpsert.add(
                App(
                    packageName = packageName,
                    label = label,
                    versionCode = versionCode,
                    versionName = versionName,
                    isSystem = ((pkgInfo.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0,
                    flags = pkgInfo.applicationInfo?.flags ?: 0
                )
            )

            if (isAppChanged) {
                packagesToScan.add(pkgInfo)
            }
        }

        if (appsToUpsert.isNotEmpty()) {
            database.appDao().insertApps(*appsToUpsert.toTypedArray())
        }

        // Pass 2: now that every App row exists, scan only the apps that are new or changed
        packagesToScan.forEachIndexed { index, pkgInfo ->
            Timber.d("Scanning ${pkgInfo.packageName}...")

            if (scanPermissions) {
                permissionScanner.scanApp(pkgInfo)
            }
            if (scanLibraries) {
                libraryScanner.scanApp(pkgInfo)
            }

            val percent = ((index + 1) * 100) / packagesToScan.size.coerceAtLeast(1)
            setProgress(workDataOf(KEY_PROGRESS to percent))
        }

        // Reconcile: any app that was known but didn't turn up in this full sweep is no longer
        // installed (catches removals the uninstall broadcast missed)
        val missingPackageNames = existingApps.keys - seenPackageNames
        if (missingPackageNames.isNotEmpty()) {
            database.appDao().updateIsInstalled(missingPackageNames.toList())
        }
    }

    companion object {
        const val KEY_PROGRESS  = "progress"
        const val KEY_PACKAGE_NAME = "packageName"
        const val KEY_SCAN_LIBRARIES = "scanLibraries"
        const val KEY_SCAN_PERMISSIONS = "scanPermissions"
        const val UNIQUE_WORK_NAME = "initial-scan"

        /**
         * Enqueues a one-time worker to perform app scanning.
         * Can be triggered after boot completion or when packages change.
         *
         * @param context The application context
         * @param packageName Optional package name to scan a specific app; if empty, all apps are scanned
         * @return UUID of the enqueued work request
         */
        fun enqueue(context: Context, scanLibraries: Boolean, scanPermissions: Boolean, packageName: String = ""): UUID {
            val workRequestBuilder = OneTimeWorkRequestBuilder<ScanWorker>()
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)

            if (packageName.isNotEmpty()) {
                val inputData = workDataOf(
                    KEY_PACKAGE_NAME to packageName,
                    KEY_SCAN_LIBRARIES to scanLibraries,
                    KEY_SCAN_PERMISSIONS to scanPermissions
                )
                workRequestBuilder.setInputData(inputData)
            }
            
            val work = workRequestBuilder.build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork(UNIQUE_WORK_NAME, ExistingWorkPolicy.REPLACE, work)

            return work.id
        }
    }
}