package de.tomcory.heimdall.net.metadata;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import android.system.OsConstants;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;

import de.tomcory.heimdall.net.flow.AbstractIp4Flow;
import de.tomcory.heimdall.net.flow.Tcp4Flow;
import de.tomcory.heimdall.net.flow.Udp4Flow;
import de.tomcory.heimdall.persistence.database.entity.App;
import timber.log.Timber;

public class ProcNetQuery {

    private static final String TAG = "ProcNetQuery";

    public static App fetchData(Context context, AbstractIp4Flow flow) {
        PackageManager pm = context.getPackageManager();

        int aid;

        if(flow instanceof Tcp4Flow) {
            aid = android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
                    ? getAid(flow, new File("/proc/net/tcp6"), new File("/proc/net/tcp"))
                    : getAidQ(flow, OsConstants.IPPROTO_TCP, context);

        } else if(flow instanceof Udp4Flow) {
            aid = android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
                    ? getAid(flow, new File("/proc/net/udp6"), new File("/proc/net/udp"))
                    : getAidQ(flow, OsConstants.IPPROTO_UDP, context);

        } else {
            Timber.e("Unsupported connection type: %s", flow.getClass().getSimpleName());
            return new App("unknown");
        }

        if(aid >= 0) {
            String[] packages = pm.getPackagesForUid(aid);
            if(packages != null) {

                App app = new App(packages[0]);
                Timber.d(flow.getLocalPort().valueAsInt() + ": " + packages[0] + " (" + aid + ")");

                try {
                    app.appLabel = (String) pm.getApplicationLabel(pm.getApplicationInfo(packages[0], PackageManager.GET_META_DATA));

                } catch (PackageManager.NameNotFoundException e) {
                    Timber.e(e, "Error retrieving application metadata");
                }
                return app;

            } else {
                Timber.tag(TAG).w("No package found for AID");
            }
        }

        return new App("unknown");
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private static int getAidQ(@NonNull AbstractIp4Flow connection, int protocol, Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(cm == null) {
            return -1;
        } else {
            InetSocketAddress local = new InetSocketAddress(connection.getLocalAddr().getHostAddress(), connection.getLocalPort().valueAsInt());
            InetSocketAddress remote = new InetSocketAddress(connection.getRemoteAddr().getHostAddress(), connection.getRemotePort().valueAsInt());

            System.out.println("A: " + local.toString());
            System.out.println("B: " + remote.toString());

            System.out.println("C: " + local.getAddress());
            System.out.println("D: " + remote.getAddress());

            return cm.getConnectionOwnerUid(protocol, local, remote);
        }
    }

    private static int getAid(@NonNull AbstractIp4Flow connection, @NonNull File ip6, @NonNull File ip4) {

        File[] procNets = {ip6, ip4};

        for(File procNet : procNets) {
            BufferedReader reader;
            try {
                reader = new BufferedReader(new FileReader(procNet));
            } catch (FileNotFoundException e) {
                Timber.e(e, "Error opening /proc/net reader");
                return -1;
            }

            try {
                reader.readLine();
            } catch (IOException e) {
                Timber.e(e, "Error reading from /proc/net");
                return -1;
            }

            while(true) {
                try {
                    String line = reader.readLine();
                    if(line != null) {
                        try {
                            line = line.replaceAll("[ ]{2,}", " ").trim();
                            String[] parts = line.split(" ");
                            int localPort = Integer.parseInt(parts[1].substring(parts[1].indexOf(':') + 1), 16);
                            if(localPort == connection.getLocalPort().valueAsInt()) {
                                return Integer.parseInt(parts[7]);
                            }
                        } catch (NumberFormatException e) {
                            Timber.e(e);
                            return -1;
                        }
                    } else {
                        break;
                    }
                } catch (IOException e) {
                    Timber.e(e, "Error reading from /proc/net");
                    return -1;
                }
            }
        }
        return -1;
    }
}
