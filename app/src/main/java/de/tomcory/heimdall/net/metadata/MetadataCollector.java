package de.tomcory.heimdall.net.metadata;

import android.content.Context;

import java.lang.ref.WeakReference;
import java.util.Objects;

import de.tomcory.heimdall.net.flow.AbstractIp4Flow;
import de.tomcory.heimdall.net.flow.cache.DnsCache;
import de.tomcory.heimdall.persistence.database.TrafficDatabase;
import de.tomcory.heimdall.persistence.database.entity.App;
import de.tomcory.heimdall.persistence.database.entity.Connection;
import de.tomcory.heimdall.persistence.database.entity.Host;
import de.tomcory.heimdall.util.SecondLevelDomains;
import timber.log.Timber;

public class MetadataCollector extends Thread {
    
    private final AbstractIp4Flow flow;
    private final WeakReference<Context> contextWeakReference;

    public MetadataCollector(AbstractIp4Flow flow, Context context) {
        this.flow = flow;
        this.contextWeakReference = new WeakReference<>(context);
        Timber.d("%s Created", flow.getFlowId());
    }

    @Override
    public void run() {
        Context context = contextWeakReference.get();
        if(context != null) {

            Timber.d("%s Starting ProcNetQuery", flow.getFlowId());

            // query the /proc/net pseudo-filesystem for the package and label of the app that owns the flow
            App app = ProcNetQuery.fetchData(context, flow);

            Timber.d(flow.getFlowId() + " Completed ProcNetQuery, App is " + (app.appPackage));

            // persist the new App entity
            TrafficDatabase.getInstance().getAppDao().upsertSync(app);

            // query the DnsCache for the hostname corresponding to the flow's remote address
            String hostname = DnsCache.findHost(Objects.requireNonNull(flow.getRemoteAddr().getHostAddress()));
            String payLevelDomain = null;

            // if no hostname was found, use the IP address instead
            if(hostname == null) {
                hostname = flow.getRemoteAddr().getHostAddress();

            } else {
                // calculate the hostname's pay-level domain (e.g. google.com for www.google.com)
                String[] hostParts = hostname.split("\\.");

                Timber.d(flow.getFlowId() + " split hostname " + hostname + " into " + hostParts.length + " parts");

                if(hostParts.length >= 3 && SecondLevelDomains.matchesTld(hostParts[hostParts.length - 1]) && SecondLevelDomains.matchesSld(hostParts[hostParts.length - 2])) {
                    payLevelDomain = hostParts[hostParts.length - 3] + "." + hostParts[hostParts.length - 2] + "." + hostParts[hostParts.length - 1];

                } else if(hostParts.length >= 2) {
                    payLevelDomain = hostParts[hostParts.length - 2] + "." + hostParts[hostParts.length - 1];

                } else {
                    payLevelDomain = hostname;
                }
            }

            Host host = new Host(hostname);
            host.payLevelDomain = payLevelDomain;

            Timber.d(flow.getFlowId() + " Got hostname: " + host.hostname + " (" + (payLevelDomain == null ? "null" : host.payLevelDomain) + ")");

            Timber.d("%s Persisting Host", flow.getFlowId());

            // persist the Host entity (does not overwrite existing entries)
            TrafficDatabase.getInstance().getHostDao().insertSync(host);

            Timber.d("%s Persisting Connection", flow.getFlowId());

            // persist the Connection entity (does not overwrite existing entries)
            TrafficDatabase.getInstance().getConnectionDao().insertSync(new Connection(app.appPackage, hostname));

            Timber.d("%s Updating Flow", flow.getFlowId());

            // update flow with appPackage and hostname
            flow.setAppPackage(app.appPackage);
            flow.setHostname(hostname);
            TrafficDatabase.getInstance().addFlowToUpdateCache(flow.getDatabaseEntity());
        }
    }
}
