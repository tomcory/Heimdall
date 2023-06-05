package de.tomcory.heimdall.application

import android.app.Application
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import timber.log.Timber

class HeimdallApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        //StrictMode.enableDefaults()
        Timber.plant(Timber.DebugTree())

        // initialise a TrafficDatabase singleton instance
        if (HeimdallDatabase.init(this)) {
            Timber.d("TrafficDatabase instance created")
        }
    }
}