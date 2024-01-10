package de.tomcory.heimdall.service

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.IBinder
import androidx.core.app.NotificationCompat
import dagger.hilt.android.AndroidEntryPoint
import de.tomcory.heimdall.R
import de.tomcory.heimdall.application.HeimdallApplication
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.core.scanner.LibraryScanner
import de.tomcory.heimdall.core.scanner.PermissionScanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

@AndroidEntryPoint
class ScanService : Service() {

    @Inject lateinit var database: HeimdallDatabase
    @Inject lateinit var preferences: PreferencesDataSource
    @Inject lateinit var permissionScanner: PermissionScanner
    @Inject lateinit var libraryScanner: LibraryScanner

    private var broadcastReceiver: ScanBroadcastReceiver? = null

    override fun onCreate() {
        super.onCreate()

        Timber.d("ScanService creating...")

        // Create a notification for the foreground service
        val notification = NotificationCompat.Builder(this, HeimdallApplication.CHANNEL_ID)
            .setContentTitle("ScanService")
            .setContentText("Ready to scan freshly installed apps...")
            .setSmallIcon(R.drawable.ic_scan_active)
            .build()

        // Start the service in foreground
        startForeground(1, notification)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Timber.d("ScanService starting...")

        CoroutineScope(Dispatchers.IO).launch {

            broadcastReceiver = ScanBroadcastReceiver()

            // configure the broadcast receiver to receive broadcasts when an app is installed or uninstalled
            val filter = IntentFilter()
            filter.addAction(Intent.ACTION_PACKAGE_ADDED)
            filter.addAction(Intent.ACTION_PACKAGE_REMOVED)
            filter.addDataScheme("package")

            // register the broadcast receiver with the system
            registerReceiver(broadcastReceiver, filter)

            Timber.d("ScanBroadcastReceiver registered")
        }

        return super.onStartCommand(intent, flags, startId)
    }

    override fun onDestroy() {
        super.onDestroy()

        Timber.d("ScanService onDestroy")

        // Unregister the receiver when the service is destroyed
        broadcastReceiver?.let { unregisterReceiver(it) }
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    /**
     * This [BroadcastReceiver] is registered to receive broadcasts when an app is installed or uninstalled.
     */
    private inner class ScanBroadcastReceiver : BroadcastReceiver() {

        init {
            Timber.d("ScanBroadcastReceiver created")
        }

        override fun onReceive(context: Context, intent: Intent) {
            when(intent.action) {
                Intent.ACTION_PACKAGE_ADDED -> actionPackageAdded(context, intent.data?.schemeSpecificPart ?: "")
                Intent.ACTION_PACKAGE_REMOVED -> actionPackageRemoved(context, intent.data?.schemeSpecificPart ?: "")
            }
        }

        /**
         * This method is called when an app is installed and triggers the [PermissionScanner] and [LibraryScanner] to scan the app
         * if the user has enabled this in the settings.
         */
        private fun actionPackageAdded(context: Context, packageName: String) {
            Timber.d("App installed: $packageName")
            CoroutineScope(Dispatchers.IO).launch {

                // query the preferences to see if the user wants to scan the app on install
                val scanPermissions = preferences.permissionOnInstall.first()
                val scanLibraries = preferences.libraryOnInstall.first()

                // get the package info of the app that was installed if the user wants to scan it
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

                // insert the app's metadata into the database
                database.appDao().insertApps(
                    App(
                        packageName = packageInfo.packageName,
                        label = packageInfo.applicationInfo.loadLabel(context.packageManager).toString(),
                        versionCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                            packageInfo.longVersionCode
                        } else {
                            packageInfo.versionCode.toLong()
                        },
                        versionName = packageInfo.versionName ?: "",
                    )
                )

                // scan the app for permissions and third-party libraries if the user wants to
                if(scanPermissions) {
                    permissionScanner.scanApp(packageInfo)
                }

                if(scanLibraries) {
                    libraryScanner.scanApp(packageInfo)
                }
            }
        }

        /**
         * This method is called when an app is uninstalled and updates the app's installations status in the database.
         */
        private fun actionPackageRemoved(context: Context, packageName: String) {
            Timber.d("App uninstalled: $packageName; updating status in database")
            CoroutineScope(Dispatchers.IO).launch {
                database.appDao().updateIsInstalled(packageName)
            }
        }
    }
}