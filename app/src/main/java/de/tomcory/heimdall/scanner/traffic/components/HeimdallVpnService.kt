package de.tomcory.heimdall.scanner.traffic.components

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.preference.PreferenceManager
import de.tomcory.heimdall.R
import de.tomcory.heimdall.persistence.VpnStats
import de.tomcory.heimdall.persistence.database.HeimdallDatabase
import de.tomcory.heimdall.persistence.database.entity.Session
import de.tomcory.heimdall.ui.main.MainActivity
import de.tomcory.heimdall.ui.main.preferencesStore
import de.tomcory.heimdall.scanner.traffic.mitm.VpnComponentLaunchException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException

class HeimdallVpnService : VpnService() {
    var isVpnActive = false
        private set
    private var vpnInterface: ParcelFileDescriptor? = null
    var sessionId: Long = 0
        private set
    private var componentsActive = false
    private var componentManager: ComponentManager? = null

    private val coroutineScope = CoroutineScope(Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        Timber.d("VpnService created")
    }

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        return when(val intentExtra = intent.getIntExtra(VPN_ACTION, START_SERVICE)) {

            START_SERVICE, START_SERVICE_PROXY -> {
                val useProxy = intentExtra == START_SERVICE_PROXY

                Timber.d("Received %s", if(useProxy) "START_SERVICE_PROXY" else "START_SERVICE")

                // promote this service to the foreground to prevent it from being put to sleep
                startForeground(ONGOING_NOTIFICATION_ID, createForegroundNotification())

                CoroutineScope(Dispatchers.IO).launch {
                    val insertedIds = HeimdallDatabase.instance?.sessionDao?.insert(Session())
                    sessionId = if(!insertedIds.isNullOrEmpty()) {
                        insertedIds.first()
                    } else {
                        0
                    }

                    if(sessionId > 0) {
                        Timber.d("VpnService startup: got session, launching service components")
                        launchServiceComponents(useProxy)
                        Timber.d("VpnService started")
                        isVpnActive = true
                    } else {
                        Timber.e("VpnService startup: invalid session, service components not launched")
                        shutDown()
                    }
                }

                START_STICKY
            }

            STOP_SERVICE -> {
                Timber.d("Received STOP_SERVICE")

                CoroutineScope(Dispatchers.IO).launch {
                    shutDown()
                    isVpnActive = false
                }

                START_NOT_STICKY
            }

            else -> {
                Timber.e("Received intent with invalid VPN_ACTION value")
                START_NOT_STICKY
            }
        }
    }

    @SuppressLint("ObsoleteSdkInt")
    private fun createForegroundNotification(): Notification {

        //TODO: make it work for SDK < O
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
        val stopVpnIntent = Intent(this, NotificationIntentService::class.java)
        stopVpnIntent.action = NotificationIntentService.STOP_VPN
        val activityPendingIntent = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stopVpnPendingIntent = PendingIntent.getService(this, 0, stopVpnIntent, PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_eye_check_outline)
            .setContentTitle(getString(R.string.notification_title))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .addAction(R.drawable.ic_launcher_foreground, getString(R.string.notification_stop_vpn), stopVpnPendingIntent)
            .setContentIntent(activityPendingIntent)
            .build()
    }

    private suspend fun launchServiceComponents(useProxy: Boolean) {

        val dataStore = applicationContext.preferencesStore
        val doMitm = dataStore.data.first().mitmEnable

        // (re)initialise the Statistics singleton
        VpnStats.initialise(applicationContext)
        Timber.d("VpnStats initialised")

        // establish the VPN interface
        if (!establishInterface(useProxy)) {
            Timber.e("Unable to establish interface")
            stopSelf()
            return
        }

        // launch the traffic-handling components through the ComponentManager
        try {
            componentManager = ComponentManager(
                FileInputStream(vpnInterface?.fileDescriptor),
                FileOutputStream(vpnInterface?.fileDescriptor),
                this,
                doMitm
            )
        } catch (e: VpnComponentLaunchException) {
            Timber.e("Failed to initialise traffic handlers")
            stopVpnComponents()
            return
        }

        // getting to this point means that everything was established and launched successfully
        componentsActive = true
    }

    private fun establishInterface(useProxy: Boolean): Boolean {
        //TODO: replace SharedPreferences with DataStore
        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)

        if (vpnInterface != null) {
            Timber.i("VPN interface already established")
            return false
        } else {
            Timber.d("Beginning interface establishment")
        }
        val dnsServer = sharedPreferences.getString("dns_server", "1.1.1.1")

        val subnet = sharedPreferences.getString("vpn_subnet", "")!!.split("/").toTypedArray()
        val baseAddressString = if (subnet.size == 2 && isValidInet4Address(subnet[0])) subnet[0] else getString(R.string.default_subnet).split("/").toTypedArray()[0]
        val prefixLength = try {
            if (subnet.size == 2) subnet[1].toInt() else getString(R.string.default_subnet).split("/").toTypedArray()[1].toInt()
        } catch (e: NumberFormatException) {
            32
        }

        //TODO: I hate this, find a better way of parsing the addresses
        val dnsServerAddress: InetAddress
        val baseAddress: InetAddress
        val routeAddress: InetAddress
        try {
            dnsServerAddress = try {
                InetAddress.getByName(dnsServer)
            } catch (e: Exception) {
                Timber.d("Invalid DNS, using default")
                InetAddress.getByName("1.1.1.1")
            }
            baseAddress = InetAddress.getByName(baseAddressString)
            routeAddress = InetAddress.getByName("0.0.0.0")
        } catch (e: UnknownHostException) {
            Timber.e("Error: invalid DNS server address")
            return false
        }

        Timber.d(dnsServerAddress.hostAddress)

        val builder: Builder = Builder()
            .setSession("Heimdall")
            .addDnsServer(dnsServerAddress)
            .addAddress(baseAddress, prefixLength)
            .addRoute(routeAddress, 0)

        if(useProxy && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Timber.d("VPN attached to Proxy")
            builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1",9090))
        } else {
            Timber.d("VPN in standalone mode")
        }

        val monitoringScope = sharedPreferences.getString("monitoring_scope", "all")
        when (monitoringScope) {
            "all" -> Timber.d("Monitoring scope: all")
            "whitelist" -> Timber.d("Monitoring scope: whitelist")
            "blacklist" -> Timber.d("Monitoring scope: blacklist")
        }

        //TODO: replace with proper implementation
        try {
            builder.addDisallowedApplication("de.tomcory.heimdall")
            //TODO: add toggle for this
//            OsUtils.getSystemApps(context = this).forEach {
//                builder.addDisallowedApplication(it)
//            }
        } catch (e: Exception) {
            Timber.e("Couldn't add Heimdall package as disallowed app")
        }

        if (monitoringScope != "whitelist" && sharedPreferences.getBoolean("exclude_system", false)) {

            val systemApps = if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong() or PackageManager.MATCH_SYSTEM_ONLY.toLong()))
            } else {
                packageManager.getInstalledApplications(PackageManager.GET_META_DATA or PackageManager.MATCH_SYSTEM_ONLY)
            }

            for (packageInfo in systemApps) {
                try {
                    builder.addDisallowedApplication(packageInfo.packageName)
                } catch (e: PackageManager.NameNotFoundException) {
                    Timber.e(e, "Error adding system app to blacklist")
                }
            }
        }

        Timber.d("Ready to establish VPN interface")

        return try {
            vpnInterface = builder.establish()
            true
        } catch (e: Exception) {
            Timber.e(e, "Error establishing VPN interface")
            false
        }
    }

    private fun isValidInet4Address(address: String?): Boolean {
        if(address == null) {
            return false
        }
        val bytes = address.split(".").toTypedArray()
        if (bytes.size != 4) {
            return false
        }
        for (b in bytes) {
            try {
                val value = b.toInt()
                if (value < 0 || value > 255) {
                    return false
                }
            } catch (e: java.lang.NumberFormatException) {
                return false
            }
        }
        return true
    }

    private suspend fun shutDown() {
        if(componentsActive) {
            Timber.d("Shutting down VpnService")
            stopVpnComponents()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            Timber.d("VpnService stopped")
        }
    }

    private suspend fun stopVpnComponents() {
        withContext(Dispatchers.IO) {
            Timber.d("Stopping VPN service components")
            componentManager?.stopComponents()

            // close the VPN interface
            try {
                vpnInterface?.close()
            } catch (e: IOException) {
                Timber.e(e, "Error closing FileDescriptor")
            }

            // persist and reset the Statistics singleton
            VpnStats.close(applicationContext)

            HeimdallDatabase.instance?.sessionDao?.updateEndTime(sessionId, System.currentTimeMillis())

            // set the flag to signal that the VPN components are no longer active
            componentsActive = false
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Timber.d("VpnService onDestroy called")
        coroutineScope.launch {
            shutDown()
            Timber.d("VpnService destroyed")
        }
    }

    companion object {
        const val VPN_ACTION = "de.tomcory.heimdall.net.vpn.ACTION_START"
        const val START_SERVICE = 0
        const val STOP_SERVICE = 1
        const val START_SERVICE_PROXY = 2
        private const val CHANNEL_ID = "de.tomcory.heimdall.ui.notification.CHANNEL"
        private const val ONGOING_NOTIFICATION_ID = 235
    }
}