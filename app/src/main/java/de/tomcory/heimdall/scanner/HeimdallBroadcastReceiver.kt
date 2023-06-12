package de.tomcory.heimdall.scanner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import de.tomcory.heimdall.scanner.permission.PermissionScanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber

class HeimdallBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when(intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> actionPackageAdded(context, intent.data?.schemeSpecificPart ?: "")
            Intent.ACTION_PACKAGE_REMOVED -> actionPackageRemoved(context, intent.data?.schemeSpecificPart ?: "")
        }
    }

    private fun actionPackageAdded(context: Context, pkg: String) {
        Timber.d("App installed: $pkg")
        CoroutineScope(Dispatchers.IO).launch {
            PermissionScanner.scanGivenApp(context, pkg)
        }
    }

    private fun actionPackageRemoved(context: Context, pkg: String) {
        Timber.d("App removed: $pkg")
    }
}