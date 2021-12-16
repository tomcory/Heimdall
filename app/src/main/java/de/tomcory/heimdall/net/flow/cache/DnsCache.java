package de.tomcory.heimdall.net.flow.cache;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.LinkedHashMap;

public class DnsCache {
    private static final int MAX_SIZE = 128;

    //the singleton
    private static final DnsCache cache = new DnsCache();

    private final LinkedHashMap<String, String> hosts = new LinkedHashMap<>(MAX_SIZE) {
        @Override
        protected boolean removeEldestEntry(Entry<String, String> eldest) {
            return size() >= MAX_SIZE;
        }
    };

    @Nullable
    public static String findHost(@NonNull String ipAddress) {
        return cache.hosts.get(ipAddress);
    }

    public static void addHost(@NonNull String ipAddress, @NonNull String hostname) {
        cache.hosts.put(ipAddress, hostname);
    }
}
