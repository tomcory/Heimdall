package de.tomcory.heimdall.net.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationCompat;
import androidx.preference.PreferenceManager;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.UdpPort;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.Selector;
import java.util.Objects;
import java.util.Timer;

import de.tomcory.heimdall.R;
import de.tomcory.heimdall.net.flow.Tcp4Flow;
import de.tomcory.heimdall.net.flow.cache.FlowCache;
import de.tomcory.heimdall.persistence.BatchProcessorTask;
import de.tomcory.heimdall.persistence.database.TrafficDatabase;
import de.tomcory.heimdall.persistence.database.entity.Session;
import de.tomcory.heimdall.ui.activity.MainActivity;
import de.tomcory.heimdall.ui.notification.NotificationIntentService;
import de.tomcory.heimdall.util.StringUtils;
import io.reactivex.SingleObserver;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;
import timber.log.Timber;

public class HeimdallVpnService extends VpnService {

    public static final String VPN_ACTION = "de.tomcory.heimdall.net.vpn.ACTION_START";
    public static final int START_SERVICE = 0;
    public static final int STOP_SERVICE = 1;

    private static final String CHANNEL_ID = "de.tomcory.heimdall.ui.notification.CHANNEL";
    private static final int ONGOING_NOTIFICATION_ID = 235;
    private static final int DATABASE_BATCH_PROCESSOR_INTERVAL = 1000;

    public static final Object threadReadyMonitor = new Object();
    public static final Object selectorMonitor = new Object();

    private static boolean vpnActive = false;

    private ParcelFileDescriptor vpnInterface;
    private Session session;

    private DeviceWriteThread deviceWriteThread;
    private OutgoingTrafficHandler outgoingTrafficHandler;
    private IncomingTrafficHandler incomingTrafficHandler;
    private DevicePollThread devicePollThread;
    private Timer periodicBulkInserter;
    private FileDescriptor interrupter;

    private boolean componentsActive = false;

    @Override
    public void onCreate() {
        super.onCreate();
        Timber.d("VpnService created");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        if(intent == null) {
            Timber.d("Received empty intent");
            shutDown();
            vpnActive = false;
            return START_NOT_STICKY;
        }

        int action = intent.getIntExtra(VPN_ACTION, START_SERVICE);

        if(action == START_SERVICE) {
            Timber.d("Received START_SERVICE");
            // promote this service to the foreground to prevent it from being put to sleep
            startForeground(ONGOING_NOTIFICATION_ID, createForegroundNotification());

            session = new Session();
            session.timestamp = System.currentTimeMillis();

            // launch all components of the service in a separate thread to prevent the UI thread from freezing
            TrafficDatabase.getInstance().getSessionDao().insert(session).subscribeOn(Schedulers.io()).subscribe(new SingleObserver<Long>() {
                @Override
                public void onSubscribe(@NonNull Disposable d) {
                    //TODO: implement
                }

                @Override
                public void onSuccess(@NonNull Long rowId) {
                    session.sessionId = rowId;
                    launchServiceComponents();
                    Timber.d("VpnService started");
                    vpnActive = true;
                }

                @Override
                public void onError(@NonNull Throwable e) {
                    Timber.e(e, "Error starting VpnService");
                }
            });

            return START_STICKY;

        } else if(action == STOP_SERVICE) {
            Timber.d("Received STOP_SERVICE");
            shutDown();
            vpnActive = false;
            return START_NOT_STICKY;

        } else {
            Timber.e("Unknown VPN_ACTION value: %s", action);
            return START_NOT_STICKY;
        }
    }

    private Notification createForegroundNotification() {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW);
            channel.setDescription(getString(R.string.channel_description));

            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            } else {
                Timber.e("Error creating NotificationChannel: NotificationManager is null");
            }
        }

        Intent stopVpnIntent = new Intent(this, NotificationIntentService.class);
        stopVpnIntent.setAction(NotificationIntentService.STOP_VPN);

        PendingIntent activityPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), 0);
        PendingIntent stopVpnPendingIntent = PendingIntent.getService(this, 0, stopVpnIntent, 0);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_eye_check_outline)
                .setContentTitle(getString(R.string.notification_title))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .addAction(R.drawable.ic_launcher_foreground, getString(R.string.notification_stop_vpn), stopVpnPendingIntent)
                .setContentIntent(activityPendingIntent)
                .build();
    }

    private void launchServiceComponents() {

        // establish the VPN interface
        if(!establishInterface()) {
            stopSelf();
            return;
        }

        // set up the pipes that are used to poll the VPN interface for new outgoing packets
        FileDescriptor[] pipes;
        try {
            pipes = Os.pipe();

        } catch (ErrnoException e) {
            Timber.e(e, "Error getting pipes from OS");
            shutDown();
            return;
        }
        interrupter = pipes[0];
        FileDescriptor interrupted = pipes[1];

        // set up the NIO selector that is used to poll the outgoing sockets for incoming packets
        Selector socketSelector;
        try {
            socketSelector = Selector.open();

        } catch (IOException e) {
            Timber.e(e, "Error opening selector");
            shutDown();
            return;
        }

        // initialise the pcap4j configuration now to improve performance during traffic handling
        if(!initialisePcap4j()) {
            return;
        }

        // set flag to signal that the VPN's components are active
        synchronized (this) {
            componentsActive = true;
        }

        // start the thread that writes incoming packets to the VPN interface
        deviceWriteThread = new DeviceWriteThread("DeviceWriteThread", new FileOutputStream(vpnInterface.getFileDescriptor()));

        // wait for the DeviceWriteThread's looper and handler to be ready before continuing
        synchronized (threadReadyMonitor) {
            try {
                deviceWriteThread.start();
                threadReadyMonitor.wait();
            } catch (InterruptedException e) {
                Timber.e(e, "Error waiting for DeviceWriteThread to initialise");
                shutDown();
                return;
            }
        }

        // start the thread that handles outgoing traffic
        outgoingTrafficHandler = new OutgoingTrafficHandler("OutgoingTrafficHandler", deviceWriteThread.getHandler(), socketSelector, this);

        // wait for the OutgoingTrafficHandler's looper and handler to be ready before continuing
        synchronized (threadReadyMonitor) {
            try {
                outgoingTrafficHandler.start();
                threadReadyMonitor.wait();
            } catch (InterruptedException e) {
                Timber.e(e, "Error waiting for OutgoingTrafficHandler to initialise");
                shutDown();
                return;
            }
        }

        // start the thread that handles incoming traffic
        incomingTrafficHandler = new IncomingTrafficHandler("IncomingTrafficHandler", deviceWriteThread.getHandler(), socketSelector);
        incomingTrafficHandler.start();

        // start the thread that reads outgoing packets from the VPN interface
        devicePollThread = new DevicePollThread("DevicePollThread", new FileInputStream(vpnInterface.getFileDescriptor()), interrupted, outgoingTrafficHandler.getHandler());
        devicePollThread.start();

        //TODO: only start if defined by preferences (i.e. user wants to capture all packets)
        periodicBulkInserter = new Timer(true);
        periodicBulkInserter.schedule(new BatchProcessorTask(), DATABASE_BATCH_PROCESSOR_INTERVAL, DATABASE_BATCH_PROCESSOR_INTERVAL);
    }

    private boolean initialisePcap4j() {
        Timber.d("Initialising pcap4j configuration");

        // this is just the raw dump of a random TCP SYN packet used for the packet parser
        byte[] rawPacket = {0x45, 0x00, 0x00, 0x3C, 0x15, (byte) 0xD4, 0x40, 0x00, 0x40, 0x06,
                (byte) 0xC1, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x6D, 0x14, (byte) 0x8B, 0x63, 0x00, 0x00,
                0x00, 0x00, (byte) 0xA0, 0x02, (byte) 0xFF, (byte) 0xFF, (byte) 0xB1, 0x50, 0x00, 0x00,
                0x02, 0x04, 0x05, (byte) 0xB4, 0x04, 0x02, 0x08, 0x0A, 0x00, (byte) 0xF8,
                (byte) 0x9E, (byte) 0xB7, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06};

        // by building a packet from raw data we kick off the slow pcap4j initial properties loading process now instead of when the actual first packet is processed
        IpV4Packet parsedPacket;
        try {
            parsedPacket = IpV4Packet.newPacket(rawPacket, 0, rawPacket.length);

        } catch (IllegalRawDataException e) {
            Timber.e(e, "Error initialising pcap4j packet parser");
            return false;
        }

        // using packet builders for the first time is also slow, so we do it now

        // build a TCP packet
        try {
            Tcp4Flow.buildRstForUnknownConnection(parsedPacket);

        } catch (Exception e) {
            Timber.e(e, "Error initialising pcap4j TCP packet builder");
            return false;
        }

        // build a UDP packet
        try {
            new UdpPacket.Builder()
                    .srcAddr(parsedPacket.getHeader().getSrcAddr())
                    .dstAddr(parsedPacket.getHeader().getSrcAddr())
                    .srcPort(UdpPort.getInstance((short) 0))
                    .dstPort(UdpPort.getInstance((short) 0))
                    .correctChecksumAtBuild(true)
                    .build();

        } catch (Exception e) {
            Timber.e(e, "Error initialising pcap4j TCP packet builder");
            return false;
        }

        Timber.d("Completed pcap4j configuration");
        return true;
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private boolean establishInterface() {
        if(vpnInterface != null) {
            Timber.i("VPN interface already established");
            return false;
        }

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

        String dnsServer = sharedPreferences.getString("dns_server", "");
        if(!StringUtils.isValidIpAddress(Objects.requireNonNull(dnsServer))) {
            dnsServer = getString(R.string.default_dns);
        }

        String[] subnet = Objects.requireNonNull(sharedPreferences.getString("vpn_subnet", "")).split("/");
        String baseAddress = subnet.length == 2 && StringUtils.isValidIpAddress(subnet[0]) ? subnet[0] : getString(R.string.default_subnet).split("/")[0];
        int prefixLength;
        try {
            prefixLength = subnet.length == 2 ? Integer.parseInt(subnet[1]) : Integer.parseInt(getString(R.string.default_subnet).split("/")[1]);
        } catch(NumberFormatException e) {
            prefixLength = 32;
        }

        Builder builder = new Builder()
                .setSession("Heimdall")
                .addDnsServer(dnsServer)
                .addAddress(baseAddress, prefixLength)
                .addRoute("0.0.0.0", 0);

        String monitoringScope = sharedPreferences.getString("monitoring_scope", "all");

        switch (Objects.requireNonNull(monitoringScope)) {
            case "all":
                Timber.d("Monitoring scope: all");
                //TODO: implement
                break;
            case "whitelist":
                Timber.d("Monitoring scope: whitelist");
                //TODO: implement
                break;
            case "blacklist":
                Timber.d("Monitoring scope: blacklist");
                //TODO: implement
                break;
        }

        //TODO: replace with proper implementation
        try {
            builder.addDisallowedApplication("de.tomcory.heimdall");
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }

        if(!monitoringScope.equals("whitelist") && sharedPreferences.getBoolean("exclude_system", false)) {
            for (ApplicationInfo packageInfo : getPackageManager().getInstalledApplications(PackageManager.GET_META_DATA | PackageManager.MATCH_SYSTEM_ONLY)) {
                try {
                    builder.addDisallowedApplication(packageInfo.packageName);
                } catch (PackageManager.NameNotFoundException e) {
                    Timber.e(e, "Error adding system app to blacklist");
                }
            }
        }

        vpnInterface = builder.establish();

        if(vpnInterface != null) {
            Timber.d("VPN interface successfully established");
            return true;
        } else {
            Timber.e("Error establishing VPN interface");
            return false;
        }
    }

    private void shutDown() {
        synchronized (this) {
            if(componentsActive) {
                stopVpnComponents();
            }
        }
        stopForeground(true);
        stopSelf();

        Timber.d("VpnService stopped");
    }

    private void stopVpnComponents() {
        Timber.d("Stopping VPN service components");

        // stop the DevicePollthread
        if(devicePollThread != null) {
            devicePollThread.interrupt();

            // closing the interrupter pipe stops the DevicePollThread's polling
            try {
                Os.close(interrupter);
            } catch (ErrnoException e) {
                Timber.e(e, "Error closing interrupter pipe");
            }
        }

        // stop the OutgoingTrafficHandler
        if(outgoingTrafficHandler != null) {
            outgoingTrafficHandler.quit();
        }

        // stop the IncomingTrafficHandler
        if(incomingTrafficHandler != null) {
            incomingTrafficHandler.interrupt();
        }

        // stop the DeviceWriteThread
        if(deviceWriteThread != null) {
            deviceWriteThread.quit();
        }

        // close the VPN interface
        try {
            vpnInterface.close();
        } catch (IOException e) {
            Timber.e(e, "Error closing FileDescriptor");
        }

        // clear the ConnectionCache
        FlowCache.closeAllandClear();

        // cancel the Timer that inserts/updates flows and packets in batches
        if(periodicBulkInserter != null) {
            periodicBulkInserter.cancel();

            // run the bulk inserter task once more to make sure we handle the last batch
            new Timer(false).schedule(new BatchProcessorTask(), 0);
        }

        session.duration = System.currentTimeMillis() - session.timestamp;
        TrafficDatabase.getInstance().getSessionDao().update(session).subscribeOn(Schedulers.io()).subscribe();

        // set the flag to signal that the VPN components are no longer active
        componentsActive = false;
    }

    @Override
    public void onRevoke() {
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        synchronized (this) {
            if(componentsActive) {
                stopVpnComponents();
            }
        }
    }

    public long getSessionId() {
        return session.sessionId;
    }

    public static boolean isVpnActive() {
        return vpnActive;
    }
}