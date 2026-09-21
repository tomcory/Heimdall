package de.tomcory.heimdall.service

import android.annotation.SuppressLint
import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import dagger.hilt.android.AndroidEntryPoint
import de.tomcory.heimdall.MonitoringScopeApps.*
import de.tomcory.heimdall.R
import de.tomcory.heimdall.application.HeimdallApplication
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.core.util.AppFinder
import de.tomcory.heimdall.core.util.InetAddressUtils
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.components.RoomDatabaseConnector
import de.tomcory.heimdall.core.vpn.mitm.VpnComponentLaunchException
import de.tomcory.heimdall.ui.main.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import javax.inject.Inject

@AndroidEntryPoint
class HeimdallVpnService : VpnService() {

    @Inject lateinit var preferences: PreferencesDataSource
    @Inject lateinit var database: HeimdallDatabase

    private val coroutineScope = CoroutineScope(Dispatchers.Default)
    private var componentManager: ComponentManager? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var startTime: Long = 0
    private var notificationUpdateHandler: Handler? = null
    private var notificationUpdateRunnable: Runnable? = null

    private var componentsActive = false

    /**
     * This function is called when the service is first created. It is responsible for initialising
     * the service.
     * @see [onStartCommand]
     */
    override fun onCreate() {
        super.onCreate()
        Timber.d("VpnService created")
    }

    /**
     * This function is called when the service is started. It is responsible for launching the
     * VPN components and establishing the VPN interface.
     * @param intent The intent that was used to start the service.
     * @param flags Flags indicating how the service was started.
     * @param startId A unique integer representing this specific request to start.
     * @return The return value indicates what semantics the system should use for the service's
     * current started state. Is either [android.app.Service.START_STICKY] if the received intent is valid
     * or [android.app.Service.START_NOT_STICKY] if the intent's extra is invalid.
     * @see [START_SERVICE]
     * @see [STOP_SERVICE]
     */
    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        val existingSessionId = intent.getLongExtra("de.tomcory.heimdall.core.vpn.SESSION_ID", -1)

        return when(intent.getIntExtra(VPN_ACTION, START_SERVICE)) {

            START_SERVICE -> {
                startTime = System.currentTimeMillis()

                // promote this service to the foreground to prevent it from being put to sleep
                startForeground(ONGOING_NOTIFICATION_ID, createForegroundNotification())
                startNotificationUpdates()

                // launch the VPN components on a background thread
                CoroutineScope(Dispatchers.IO).launch {
                    Timber.d("Launching service components...")
                    launchServiceComponents(existingSessionId)
                    Timber.d("VpnService started")
                    preferences.setVpnActive(true)
                    preferences.setVpnLastUpdated(System.currentTimeMillis())
                }

                START_STICKY
            }

            STOP_SERVICE -> {
                Timber.d("Received STOP_SERVICE")

                // shut down the VPN components on a background thread
                CoroutineScope(Dispatchers.IO).launch {
                    shutDown()
                }

                START_NOT_STICKY
            }

            else -> {
                Timber.e("Received intent with invalid VPN_ACTION value")
                START_NOT_STICKY
            }
        }
    }

    /**
     * Creates a notification that is displayed while the service is running.
     * @return The notification to be displayed.
     * @see [startForeground]
     */
    @SuppressLint("ObsoleteSdkInt")
    private fun createForegroundNotification(): Notification {

        val notificationIntent = Intent(this, MainActivity::class.java)
        val stopVpnIntent = Intent(this, NotificationActionReceiver::class.java)
        stopVpnIntent.action = NotificationActionReceiver.STOP_VPN
        val activityPendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, PendingIntent.FLAG_IMMUTABLE)
        val stopVpnPendingIntent =
            PendingIntent.getBroadcast(this, 0, stopVpnIntent, PendingIntent.FLAG_IMMUTABLE)

        val elapsedTime = System.currentTimeMillis() - startTime
        val formattedTime = formatElapsedTime(elapsedTime)

        var vpnModeText = ""

        runBlocking {
            val mitmEnabled = preferences.mitmEnable.first()
            vpnModeText = if (mitmEnabled) "MITM-VPN" else "BASE"
        }

        return NotificationCompat.Builder(this, HeimdallApplication.CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_scan_active)
            .setContentTitle(getString(R.string.notification_title_vpn) + " ($vpnModeText)")
            .setContentText(getString(R.string.notification_text_vpn) + " ($formattedTime)")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setOngoing(true)
            .addAction(R.drawable.ic_cancel, getString(R.string.notification_stop_vpn), stopVpnPendingIntent)
            .setContentIntent(activityPendingIntent)
            .build()
    }

    private fun formatElapsedTime(elapsedTime: Long): String {
        val hours = java.util.concurrent.TimeUnit.MILLISECONDS.toHours(elapsedTime)
        val minutes = java.util.concurrent.TimeUnit.MILLISECONDS.toMinutes(elapsedTime) % 60
        val seconds = java.util.concurrent.TimeUnit.MILLISECONDS.toSeconds(elapsedTime) % 60
        return String.format("%02d:%02d:%02d", hours, minutes, seconds)
    }

    private fun startNotificationUpdates() {
        notificationUpdateHandler = Handler(Looper.getMainLooper())
        notificationUpdateRunnable = object : Runnable {
            override fun run() {
                try {
                    val notification = createForegroundNotification()
                    val notificationManager =
                        NotificationManagerCompat.from(this@HeimdallVpnService)

                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                        checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
                    ) {
                        notificationManager.notify(ONGOING_NOTIFICATION_ID, notification)
                    }

                    notificationUpdateHandler?.postDelayed(this, NOTIFICATION_UPDATE_INTERVAL)
                } catch (e: Exception) {
                    Timber.e(e, "Error updating notification")
                }
            }
        }
        notificationUpdateHandler?.post(notificationUpdateRunnable!!)
    }

    private fun stopNotificationUpdates() {
        notificationUpdateRunnable?.let {
            notificationUpdateHandler?.removeCallbacks(it)
        }
        notificationUpdateHandler = null
        notificationUpdateRunnable = null
    }

    /**
     * Launches the VPN components. This function is responsible for establishing the VPN interface
     * and launching the traffic-handling threads via the [ComponentManager].
     * @return Whether the VPN interface was established successfully.
     * @see [onStartCommand]
     */
    private suspend fun launchServiceComponents(existingSessionId: Long) {

        // determine whether to launch in MitM mode
        val doMitm = preferences.mitmEnable.first()

        Timber.d("MitM mode: $doMitm")

        // establish the VPN interface
        if (!establishInterface(doMitm)) {
            // shut down the VPN components if the interface could not be established
            stopSelf()
            return
        }

        // launch the traffic-handling components through the ComponentManager
        try {
            componentManager = ComponentManager(
                outboundStream = FileInputStream(vpnInterface?.fileDescriptor),
                inboundStream = FileOutputStream(vpnInterface?.fileDescriptor),
                databaseConnector = RoomDatabaseConnector(database),
                context = this,
                appFinder = AppFinder(this),
                doMitm = doMitm,
                existingSessionId = existingSessionId,
                keyStoreDir = File(this.filesDir, "keystore"),
                protectDatagramSocket = { socket -> protect(socket) },
                protectSocket = { socket -> protect(socket) }
            )
        } catch (e: VpnComponentLaunchException) {
            // shut down the VPN components if the ComponentManager could launch the components
            Timber.e("Failed to initialise VPN components")
            stopVpnComponents()
            return
        }

        // getting to this point means that everything was established and launched successfully
        componentsActive = true
    }

    /**
     * Configures the [VpnService.Builder] based on the configuration stored in the datastore
     * and establishes the VPN interface.
     * @return Whether the VPN interface was established successfully.
     * @see [launchServiceComponents]
     */
    private suspend fun establishInterface(doMitm: Boolean): Boolean {

        // only establish the VPN interface if it is not already established
        if (vpnInterface != null) {
            Timber.i("VPN interface already established")
            return false
        } else {
            Timber.d("Beginning interface establishment")
        }

        // prepare to parse the DNS server address, route address and subnet base address to InetAddress objects
        val dnsServer = preferences.vpnDnsServer.first()
        val subnet = preferences.vpnBaseAddress.first().split("/").toTypedArray()
        val route = preferences.vpnRoute.first().split("/").toTypedArray()
        val dnsServerAddress: InetAddress
        val subnetBaseAddress: InetAddress
        val routeBaseAddress: InetAddress

        // InetAddress.getByName() is a blocking call, so we run the address validations on the IO dispatcher
        withContext(Dispatchers.IO) {

            // validate and parse the DNS server address
            dnsServerAddress = try {
                InetAddressUtils.stringToInetAddress(dnsServer)
            } catch (e: UnknownHostException) {
                Timber.w("Invalid subnet base address, using default")
                InetAddressUtils.stringToInetAddress(
                    preferences.initialValues.vpnDnsServerInitial
                )
            }

            // validate and parse the subnet base address
            subnetBaseAddress = try {
                InetAddress.getByName(subnet[0])
            } catch (e: UnknownHostException) {
                Timber.w("Invalid subnet base address, using default")
                InetAddressUtils.stringToInetSocketAddress(
                    preferences.initialValues.vpnDnsServerInitial.split("/").toTypedArray()[0]
                )!!.address
            }

            // validate and parse the route base address
            routeBaseAddress = try {
                InetAddress.getByName(route[0])
            } catch (e: UnknownHostException) {
                Timber.w("Invalid route address, using default")
                InetAddressUtils.stringToInetSocketAddress(
                    preferences.initialValues.vpnDnsServerInitial.split("/").toTypedArray()[0]
                )!!.address
            }
        }

        // parse the subnet prefix length
        val subnetPrefix = try {
            if (subnet.size == 2) {
                subnet[1].toInt()
            } else {
                Timber.e("Invalid subnet prefix length, using default")
                preferences.initialValues.vpnBaseAddressInitial.split("/").toTypedArray()[1].toInt()
            }
        } catch (e: NumberFormatException) {
            Timber.e("Invalid subnet prefix length, using default")
            preferences.initialValues.vpnBaseAddressInitial.split("/").toTypedArray()[1].toInt()
        }

        // parse the route prefix length
        val routePrefix = try {
            if (route.size == 2) {
                route[1].toInt()
            } else {
                Timber.e("Invalid route prefix length, using default")
                preferences.initialValues.vpnRouteInitial.split("/").toTypedArray()[1].toInt()
            }
        } catch (e: NumberFormatException) {
            Timber.e("Invalid route prefix length, using default")
            preferences.initialValues.vpnRouteInitial.split("/").toTypedArray()[1].toInt()
        }

        // configure the VPN interface builder
        val builder: Builder = Builder()
            .setSession("Heimdall")
            .addDnsServer(dnsServerAddress)
            .addAddress(subnetBaseAddress, subnetPrefix)
            .addRoute(routeBaseAddress, routePrefix)

        Timber.d("VPN in standalone mode")

        // get the VPN monitoring scope from the preferences
        val monitoringScope = preferences.vpnMonitoringScope.first()
        Timber.d("VPN monitoring scope: $monitoringScope")

        val blacklist = mutableListOf<String>()
        val whitelist = mutableListOf<String>()

        // if the monitoring scope excludes system apps, add them to the builder's blacklist
        if(monitoringScope == APPS_NON_SYSTEM || monitoringScope == APPS_NON_SYSTEM_BLACKLIST) {
            // get a list of all system apps...
            val systemApps = if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong() or PackageManager.MATCH_SYSTEM_ONLY.toLong()))
            } else {
                packageManager.getInstalledApplications(PackageManager.GET_META_DATA or PackageManager.MATCH_SYSTEM_ONLY)
            }

            // ...and add them all to the builder's blacklist
            for (packageInfo in systemApps) {
                try {
                    blacklist.add(packageInfo.packageName)
                    builder.addDisallowedApplication(packageInfo.packageName)
                } catch (e: PackageManager.NameNotFoundException) {
                    Timber.e(e, "Error adding system app to blacklist")
                }
            }
        }

        // if the monitoring scope excludes blacklisted apps, add them to the builder's blacklist
        if(monitoringScope == APPS_BLACKLIST || monitoringScope == APPS_NON_SYSTEM_BLACKLIST) {
            for(packageName in preferences.vpnBlacklistApps.first().filter { it != "de.tomcory.heimdall" }) {
                try {
                    blacklist.add(packageName)
                    builder.addDisallowedApplication(packageName)
                } catch (e: PackageManager.NameNotFoundException) {
                    Timber.e("Cannot add non-installed app to VPN blacklist: $packageName")
                }
            }
        }

        // if the monitoring scope includes whitelisted apps, add them to the builder's whitelist
        if(monitoringScope == APPS_WHITELIST) {
            for(packageName in preferences.vpnWhitelistApps.first().filter { it != "de.tomcory.heimdall" }) {
                try {
                    whitelist.add(packageName)
                    builder.addAllowedApplication(packageName)
                } catch (e: PackageManager.NameNotFoundException) {
                    Timber.e("Cannot add non-installed app to VPN whitelist: $packageName")
                }
            }
        } else {
            // if we're not using a whitelist, we have to add Heimdall to the blacklist so that we don't monitor ourselves
            blacklist.add("de.tomcory.heimdall")
            builder.addDisallowedApplication("de.tomcory.heimdall")

            // if we're performing MitM, we also have to add Chrome to the blacklist because it doesn't work with MitM
            if(doMitm && !blacklist.contains("com.android.chrome")) {
                blacklist.add("com.android.chrome")
                builder.addDisallowedApplication("com.android.chrome")
            }
        }

        val debugString = StringBuilder()
        debugString.append("dnsServerAddress: ${dnsServerAddress.hostAddress}\n")
        debugString.append("subnetBaseAddress: ${subnetBaseAddress.hostAddress}\n")
        debugString.append("subnetPrefix: $subnetPrefix\n")
        debugString.append("routeBaseAddress: ${routeBaseAddress.hostAddress}\n")
        debugString.append("routePrefix: $routePrefix\n")
        debugString.append("monitoringScope: $monitoringScope\n")
        debugString.append("blacklist:\n - ${blacklist.joinToString("\n - ")}\n")
        debugString.append("whitelist:\n - ${whitelist.joinToString("\n - ")}\n")
        Timber.i(debugString.toString())

        // establish the VPN interface using the builder we just configured
        Timber.d("Ready to establish VPN interface")
        return try {
            vpnInterface = builder.establish()
            Timber.d("VPN interface established")
            true
        } catch (e: Exception) {
            Timber.e(e, "Error establishing VPN interface")
            false
        }
    }

    /**
     * Shuts down the VPN components and stops the service.
     * @see [stopVpnComponents]
     * @see [stopSelf]
     */
    private suspend fun shutDown() {
        if(componentsActive) {
            Timber.d("Shutting down VpnService")
            stopVpnComponents()
            stopNotificationUpdates()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            preferences.setVpnActive(false)
            preferences.setVpnLastUpdated(System.currentTimeMillis())
            Timber.d("VpnService stopped")
        }
    }

    /**
     * Stops the VPN components.
     * @see [componentManager]
     */
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

            // set the flag to signal that the VPN components are no longer active
            componentsActive = false
        }
    }

    /**
     * Handles the destruction of the service by gracefully shutting down the VPN components via [shutDown].
     */
    override fun onDestroy() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopNotificationUpdates()
        Timber.d("VpnService onDestroy called")
        coroutineScope.launch {
            shutDown()
            Timber.d("VpnService destroyed")
        }
        super.onDestroy()
    }

    companion object {
        /**
         * Global action identifier for intents related to the VPN service lifecycle.
         */
        const val VPN_ACTION = "de.tomcory.heimdall.net.vpn.ACTION_START"

        /**
         * Intent extra code for starting the VPN service.
         */
        const val START_SERVICE = 0

        /**
         * Intent extra code for stopping the VPN service.
         */
        const val STOP_SERVICE = 1

        /**
         * Notification ID for the foreground notification.
         */
        private const val ONGOING_NOTIFICATION_ID = 235

        /**
         * Interval for updating the foreground notification.
         */
        private const val NOTIFICATION_UPDATE_INTERVAL = 1000L
    }
}