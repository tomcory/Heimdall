package de.tomcory.heimdall.application

import android.app.Application
import android.content.Intent
import android.content.IntentFilter
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.scanner.HeimdallBroadcastReceiver
import de.tomcory.heimdall.scanner.library.LibraryScanner
import de.tomcory.heimdall.scanner.permission.PermissionScanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber

class HeimdallApplication : Application() {

    private var broadcastReceiver: HeimdallBroadcastReceiver? = null

    override fun onCreate() {
        super.onCreate()
        //StrictMode.enableDefaults()

        CoroutineScope(Dispatchers.IO).launch {
            Timber.plant(Timber.DebugTree())

            if (HeimdallDatabase.init(this@HeimdallApplication)) {
                Timber.d("Database instance created")
            }

            broadcastReceiver = HeimdallBroadcastReceiver(
                LibraryScanner.create(),
                PermissionScanner()
            )

            val filter = IntentFilter()
            filter.addAction(Intent.ACTION_PACKAGE_ADDED)
            filter.addAction(Intent.ACTION_PACKAGE_REMOVED)
            filter.addDataScheme("package")
            registerReceiver(broadcastReceiver, filter)

            Timber.d("HeimdallBroadcastReceiver registered")
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        Timber.d("Terminating")
        broadcastReceiver?.let { unregisterReceiver(it) }
        Timber.uprootAll()
    }
}