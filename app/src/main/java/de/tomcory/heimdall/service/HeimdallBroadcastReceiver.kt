package de.tomcory.heimdall.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.scanner.ScanManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

class HeimdallBroadcastReceiver (
    private val scanManager: ScanManager,
) : BroadcastReceiver() {

    @Inject lateinit var database: HeimdallDatabase

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
            scanManager.scanApp(context, packageName)
        }
    }

    private fun actionPackageRemoved(context: Context, packageName: String) {
        Timber.d("App removed: $packageName")
        CoroutineScope(Dispatchers.IO).launch {
            database.appDao().updateIsInstalled(packageName)
        }
    }
}