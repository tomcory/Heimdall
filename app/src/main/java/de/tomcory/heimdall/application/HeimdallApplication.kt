package de.tomcory.heimdall.application

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import dagger.hilt.android.HiltAndroidApp
import de.tomcory.heimdall.Preferences
import de.tomcory.heimdall.R
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesSerializer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber

@Deprecated("Use Hilt dependency injection instead.")
val Context.preferencesStore: DataStore<Preferences> by dataStore(
    fileName = "preferences.pb",
    serializer = PreferencesSerializer
)

@HiltAndroidApp
class HeimdallApplication : Application() {

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

        CoroutineScope(Dispatchers.IO).launch {
            Timber.plant(Timber.DebugTree())

            if (HeimdallDatabase.init(this@HeimdallApplication)) {
                Timber.d("Database instance created")
            }
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