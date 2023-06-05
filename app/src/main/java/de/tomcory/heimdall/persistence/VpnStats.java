package de.tomcory.heimdall.persistence;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;

public class VpnStats {

    //the singleton
    private static VpnStats instance = new VpnStats();

    private boolean initalised = false;

    private long initialConnections = 0;
    private long initialPackets = 0;
    private long initialBytesOut = 0;
    private long initialBytesIn = 0;

    private long sessionConnections = 0;
    private long sessionPackets = 0;
    private long sessionBytesOut = 0;
    private long sessionBytesIn = 0;

    public static synchronized void initialise(Context context) {
        if(!instance.initalised) {
            SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
            instance.initialConnections = sharedPreferences.getLong("total_connections", 0);
            instance.initialPackets = sharedPreferences.getLong("total_packets", 0);
            instance.initialBytesOut = sharedPreferences.getLong("total_bytes_out", 0);
            instance.initialBytesIn = sharedPreferences.getLong("total_bytes_in", 0);

            instance.initalised = true;
        }
    }

    public static synchronized void close(Context context) {
        if(instance.initalised) {

            instance.initialConnections += instance.sessionConnections;
            instance.initialPackets += instance.sessionPackets;
            instance.initialBytesOut += instance.sessionBytesOut;
            instance.initialBytesIn += instance.sessionBytesIn;

            SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
            sharedPreferences.edit()
                    .putLong("total_connections", instance.initialConnections)
                    .putLong("total_packets", instance.initialPackets)
                    .putLong("total_bytes_out", instance.initialBytesOut)
                    .putLong("total_bytes_in", instance.initialBytesIn)
                    .apply();

            instance.sessionConnections = 0;
            instance.sessionPackets = 0;
            instance.sessionBytesOut = 0;
            instance.sessionBytesIn = 0;

            instance.initalised = false;
        }
    }

    public static synchronized long getTotalConnections() {
        return instance.initialConnections + instance.sessionConnections;
    }

    public static synchronized long getTotalPackets() {
        return instance.initialPackets + instance.sessionPackets;
    }

    public static synchronized long getTotalBytesIn() {
        return instance.initialBytesIn + instance.sessionBytesIn;
    }

    public static synchronized long getTotalBytesOut() {
        return instance.initialBytesOut + instance.sessionBytesOut;
    }

    public static synchronized long getSessionConnections() {
        return instance.sessionConnections;
    }

    public static synchronized long getSessionPackets() {
        return instance.sessionPackets;
    }

    public static synchronized long getSessionBytesIn() {
        return instance.sessionBytesIn;
    }

    public static long getSessionBytesOut() {
        return instance.sessionBytesOut;
    }

    public static synchronized void increaseSessionConnections(int amount) {
        instance.sessionConnections += amount;
    }

    public static synchronized void increaseSessionPackets(int amount) {
        instance.sessionPackets += amount;
    }

    public static synchronized void increaseSessionBytesIn(int amount) {
        instance.sessionBytesIn += amount;
    }

    public static synchronized void increaseSessionBytesOut(int amount) {
        instance.sessionBytesOut += amount;
    }

    public static void increaseSessionStatsOut(byte[] packet) {
        increaseSessionBytesOut(packet.length);
        increaseSessionPackets(1);
    }

    public static void increaseSessionStatsIn(byte[] packet) {
        increaseSessionBytesIn(packet.length);
        increaseSessionPackets(1);
    }
}
