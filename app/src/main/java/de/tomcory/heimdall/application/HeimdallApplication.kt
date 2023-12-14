package de.tomcory.heimdall.application

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import dagger.hilt.android.HiltAndroidApp
import de.tomcory.heimdall.R
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

@HiltAndroidApp
class HeimdallApplication : Application() {

    @Inject
    lateinit var preferences: PreferencesDataSource

    override fun onCreate() {
        super.onCreate()
        //StrictMode.enableDefaults()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW)
            channel.description = getString(R.string.channel_description)
            val nm = getSystemService(NotificationManager::class.java)
            if (nm != null) {
                nm.createNotificationChannel(channel)
            } else {
                Timber.e("Error creating NotificationChannel: NotificationManager is null")
            }
        }

        // initialize Timber
        CoroutineScope(Dispatchers.IO).launch {
            Timber.plant(Timber.DebugTree())
        }

        // reset global state (necessary in case of crash or forced stop)
        CoroutineScope(Dispatchers.IO).launch {
            preferences.setVpnActive(false)
            preferences.setLibraryActive(false)
            preferences.setPermissionActive(false)
            preferences.setProxyActive(false)
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        Timber.d("Terminating application")
        Timber.uprootAll()
    }

    companion object {
        const val CHANNEL_ID = "de.tomcory.heimdall.ui.notification.CHANNEL"
    }
}