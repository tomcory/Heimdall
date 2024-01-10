package de.tomcory.heimdall.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.core.scanner.LibraryScanner
import de.tomcory.heimdall.core.scanner.PermissionScanner
import de.tomcory.heimdall.core.scanner.ScanManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

class HeimdallBroadcastReceiver : BroadcastReceiver() {

    @Inject lateinit var database: HeimdallDatabase
    @Inject lateinit var preferences: PreferencesDataSource
    @Inject lateinit var permissionScanner: PermissionScanner
    @Inject lateinit var libraryScanner: LibraryScanner

    init {
        Timber.d("HeimdallBroadcastReceiver created")
    }

    override fun onReceive(context: Context, intent: Intent) {
        when(intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> actionPackageAdded(context, intent.data?.schemeSpecificPart ?: "")
            Intent.ACTION_PACKAGE_REMOVED -> actionPackageRemoved(context, intent.data?.schemeSpecificPart ?: "")
        }
    }

    private fun actionPackageAdded(context: Context, packageName: String) {
        Timber.d("App installed: $packageName")
        CoroutineScope(Dispatchers.IO).launch {
            val scanPermissions = preferences.permissionOnInstall.first()
            val scanLibraries = preferences.libraryOnInstall.first()

            val packageInfo = if(scanPermissions || scanLibraries) {
                try {
                    context.packageManager.getPackageInfo(
                        packageName,
                        PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS
                    )
                } catch (e: PackageManager.NameNotFoundException) {
                    Timber.e("App $packageName not found, cannot scan it")
                    return@launch
                }
            } else {
                Timber.e("No scan scope set for $packageName")
                return@launch
            }

            if(scanPermissions) {
                permissionScanner.scanApp(packageInfo)
            }

            if(scanLibraries) {
                libraryScanner.scanApp(packageInfo)
            }
        }
    }

    private fun actionPackageRemoved(context: Context, packageName: String) {
        Timber.d("App removed: $packageName")
        CoroutineScope(Dispatchers.IO).launch {
            database.appDao().updateIsInstalled(packageName)
        }
    }
}