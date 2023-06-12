package de.tomcory.heimdall.application

import android.app.Application
import android.content.Intent
import android.content.IntentFilter
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.scanner.HeimdallBroadcastReceiver
import timber.log.Timber

class HeimdallApplication : Application() {

    private val broadcastReceiver = HeimdallBroadcastReceiver()

    override fun onCreate() {
        super.onCreate()
        //StrictMode.enableDefaults()
        Timber.plant(Timber.DebugTree())

        // initialise a TrafficDatabase singleton instance
        if (HeimdallDatabase.init(this)) {
            Timber.d("TrafficDatabase instance created")
        }

        val filter = IntentFilter()
        filter.addAction(Intent.ACTION_PACKAGE_ADDED)
        filter.addAction(Intent.ACTION_PACKAGE_REMOVED)
        filter.addDataScheme("package")
        registerReceiver(broadcastReceiver, filter)
    }

    override fun onTerminate() {
        super.onTerminate()
        unregisterReceiver(broadcastReceiver)
    }
}