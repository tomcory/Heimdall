package de.tomcory.heimdall.application

import android.annotation.SuppressLint
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import dagger.hilt.android.HiltAndroidApp
import de.tomcory.heimdall.R
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

@HiltAndroidApp
class HeimdallApplication : Application(), Configuration.Provider {

    @Inject lateinit var preferences: PreferencesDataSource
    @Inject lateinit var workerFactory: HiltWorkerFactory

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()

    @SuppressLint("ObsoleteSdkInt")
    override fun onCreate() {
        super.onCreate()
        //StrictMode.enableDefaults()

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

        // create notification channel
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = getString(R.string.channel_name)
            val descriptionText = getString(R.string.channel_description)
            val importance = NotificationManager.IMPORTANCE_DEFAULT
            val channel = NotificationChannel(CHANNEL_ID, name, importance).apply {
                description = descriptionText
            }
            val notificationManager: NotificationManager =
                getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
            Timber.d("NotificationChannel created")
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