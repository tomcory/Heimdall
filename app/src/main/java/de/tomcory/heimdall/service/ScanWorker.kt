package de.tomcory.heimdall.service

import android.content.Context
import android.content.pm.PackageManager
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
import kotlinx.coroutines.flow.first
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
    private val preferences by lazy { entryPoint.preferences() }
    private val permissionScanner by lazy { entryPoint.permissionScanner() }
    private val libraryScanner by lazy { entryPoint.libraryScanner() }

    override suspend fun doWork(): Result {
        return try {
            performFullScan()
            Result.success()
        } catch (t: Throwable) {
            Timber.e(t, "Initial scan failed")
            Result.failure()
        }
    }

    private suspend fun performFullScan() {
        val scanPermissions = preferences.permissionOnInstall.first()
        val scanLibraries = preferences.libraryOnInstall.first()

        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_META_DATA)
        val total = packages.size

        // Get all existing apps from database
        val existingApps = database.appDao().getAll().associateBy { it.packageName }

        packages.forEachIndexed { index, pkgInfo ->
            val packageName = pkgInfo.packageName
            val versionCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                pkgInfo.longVersionCode
            } else {
                pkgInfo.versionCode.toLong()
            }
            val versionName = pkgInfo.versionName ?: ""

            // Check if app is new or has a different version
            val existingApp = existingApps[packageName]
            val isAppChanged = existingApp == null ||
                    existingApp.versionCode != versionCode ||
                    existingApp.versionName != versionName ||
                    !existingApp.isInstalled

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

            // Only scan if the app is new or has changed
            if (isAppChanged) {
                Timber.d("Scanning $packageName (new or updated)...")

                if (scanPermissions) {
                    permissionScanner.scanApp(pkgInfo)
                }
                if (scanLibraries) {
                    libraryScanner.scanApp(pkgInfo)
                }
            }

            val percent = ((index + 1) * 100) / total
            setProgress(workDataOf(KEY_PROGRESS to percent))
        }
    }

    companion object {
        const val KEY_PROGRESS  = "progress"
        private const val UNIQUE_WORK_NAME = "initial-scan"

        /**
         * Enqueue a one‑time worker. Call from BootCompleted or Package change receivers.
         * The work is marked as expedited when quota permits; otherwise it runs as
         * non‑expedited but still starts promptly.
         */
        fun enqueue(context: Context): UUID {
            val work = OneTimeWorkRequestBuilder<ScanWorker>()
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .build()

            WorkManager.getInstance(context)
                .enqueueUniqueWork(UNIQUE_WORK_NAME, ExistingWorkPolicy.REPLACE, work)

            return work.id
        }
    }
}