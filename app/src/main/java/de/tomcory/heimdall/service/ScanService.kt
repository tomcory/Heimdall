package de.tomcory.heimdall.service

import android.app.Service
import android.content.Intent
import android.content.IntentFilter
import android.os.IBinder
import androidx.core.app.NotificationCompat
import de.tomcory.heimdall.R
import de.tomcory.heimdall.application.HeimdallApplication
import de.tomcory.heimdall.core.scanner.ScanManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber

class ScanService : Service() {
    private var broadcastReceiver: HeimdallBroadcastReceiver? = null

    override fun onCreate() {
        super.onCreate()

        Timber.d("ScanService onCreate")

        // Create a notification for the foreground service
        val notification = NotificationCompat.Builder(this, HeimdallApplication.CHANNEL_ID)
            .setContentTitle("ScanService")
            .setContentText("Ready to scan freshly installed apps...")
            .setSmallIcon(R.drawable.ic_earth)
            .build()

        // Start the service in foreground
        startForeground(1, notification)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Timber.d("ScanService onStartCommand")

        CoroutineScope(Dispatchers.IO).launch {

            broadcastReceiver = HeimdallBroadcastReceiver(
                scanManager = ScanManager.create(context = this@ScanService)
            )

            val filter = IntentFilter()
            filter.addAction(Intent.ACTION_PACKAGE_ADDED)
            filter.addAction(Intent.ACTION_PACKAGE_REMOVED)
            filter.addDataScheme("package")
            registerReceiver(broadcastReceiver, filter)

            Timber.d("HeimdallBroadcastReceiver registered")
        }

        return super.onStartCommand(intent, flags, startId)
    }

    override fun onDestroy() {
        super.onDestroy()

        Timber.d("ScanService onDestroy")

        // Unregister the receiver when the service is destroyed
        broadcastReceiver?.let { unregisterReceiver(it) }
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
}