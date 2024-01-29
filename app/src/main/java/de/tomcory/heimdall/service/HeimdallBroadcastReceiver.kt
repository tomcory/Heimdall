package de.tomcory.heimdall.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import dagger.hilt.android.AndroidEntryPoint
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

@AndroidEntryPoint
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
            Intent.ACTION_BOOT_COMPLETED -> actionBootCompleted(context)
            Intent.ACTION_PACKAGE_ADDED -> actionPackageAdded(context, intent.data?.schemeSpecificPart ?: "")
            Intent.ACTION_PACKAGE_REMOVED -> actionPackageRemoved(context, intent.data?.schemeSpecificPart ?: "")
            else -> Timber.d("Unknown intent action: ${intent.action}")
        }
    }

    /**
     * Starts the scan service. Called when the device has booted.
     */
    private fun actionBootCompleted(context: Context) {
        CoroutineScope(Dispatchers.IO).launch {
            if(preferences.bootScanService.first()) {
                val serviceIntent = Intent(context, ScanService::class.java)
                context.startService(serviceIntent)
            }

            if(preferences.bootVpnService.first()) {
                val serviceIntent = Intent(context, HeimdallVpnService::class.java)
                serviceIntent.putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.START_SERVICE)
                context.startService(serviceIntent)
            }
        }
    }

    /**
     * Scans the newly installed app. Called when an app has been installed.
     */
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

    /**
     * Updates the database to reflect that the app has been uninstalled. Called when an app has been uninstalled.
     */
    private fun actionPackageRemoved(context: Context, packageName: String) {
        Timber.d("App removed: $packageName")
        CoroutineScope(Dispatchers.IO).launch {
            database.appDao().updateIsInstalled(packageName)
        }
    }
}