package de.tomcory.heimdall.scanner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.scanner.library.LibraryScanner
import de.tomcory.heimdall.scanner.permission.PermissionScanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber

class HeimdallBroadcastReceiver(
    private val appInfoCollector: AppInfoCollector = AppInfoCollector(),
    private val libraryScanner: LibraryScanner?,
    private val permissionScanner: PermissionScanner = PermissionScanner()
) : BroadcastReceiver() {

    init {
        Timber.d("HeimdallBroadcastReceiver created %s %s",
            if(libraryScanner != null) "with libraryScanner" else "",
            if(permissionScanner != null) "with permissionScanner" else "")
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
            appInfoCollector.scanApp(context, packageName)
            permissionScanner?.scanApp(context, packageName)
            libraryScanner?.scanApp(context, packageName)
        }
    }

    private fun actionPackageRemoved(context: Context, packageName: String) {
        Timber.d("App removed: $packageName")
        CoroutineScope(Dispatchers.IO).launch {
            HeimdallDatabase.instance?.appDao?.updateIsInstalled(packageName)
        }
    }
}