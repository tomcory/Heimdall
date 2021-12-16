package de.tomcory.heimdall.application

import android.app.Application
import de.tomcory.heimdall.persistence.database.TrafficDatabase
import timber.log.Timber

class HeimdallApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        Timber.plant(Timber.DebugTree())

        // initialise a TrafficDatabase singleton instance
        if (TrafficDatabase.init(this)) {
            Timber.d("TrafficDatabase instance created")
        }
    }
}