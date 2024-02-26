package de.tomcory.heimdall.core.proxy;

import android.content.Context;

import de.tomcory.heimdall.core.database.HeimdallDatabase;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpProxyServer;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpProxyServerBootstrap;
import de.tomcory.heimdall.core.proxy.littleshoot.SelectiveMitmManager;
import de.tomcory.heimdall.core.proxy.littleshoot.SelectiveMitmManagerAdapter;
import de.tomcory.heimdall.core.proxy.littleshoot.impl.DefaultHttpProxyServer;
import de.tomcory.heimdall.core.proxy.littleshoot.mitm.CertificateSniffingMitmManager;

import java.net.InetSocketAddress;

import timber.log.Timber;

public class HeimdallHttpProxyServer {

    private final InetSocketAddress listeningAddress;
    private CertificateSniffingMitmManager mitmManager;
    private final Context context;
    private final HeimdallDatabase database;

    private HttpProxyServer server;

    public HeimdallHttpProxyServer(
            final InetSocketAddress listeningAddress,
            CertificateSniffingMitmManager mitmManager,
            Context applicationContext,
            HeimdallDatabase database
    ) {
        this.listeningAddress = listeningAddress;
        this.context = applicationContext;
        this.database = database;

        if (mitmManager != null) {
            this.mitmManager = mitmManager;
        }
    }

    private SelectiveMitmManagerAdapter getMitmManager() {
        return new SelectiveMitmManagerAdapter(mitmManager) {
            @Override
            public boolean shouldMITMPeer(String peerHost, int peerPort) {
                if (SelectiveMitmManager.whiteLsited.contains(peerHost + peerPort)) {
                    removeWhiteListed(peerHost + peerHost);
                    return false;
                }
                // HostAndPort.fromParts(peerHost, peerPort);
                return true;
            }

            @Override
            public void addWhiteListed(String hostAndPort) {
                SelectiveMitmManager.whiteLsited.add(hostAndPort);
            }

            @Override
            public void removeWhiteListed(String hostAndPort) {
                SelectiveMitmManager.whiteLsited.remove(hostAndPort);
            }
        };
    }

    public void start() {
        HttpProxyServerBootstrap serverBootstrap = DefaultHttpProxyServer
                        .bootstrap()
                        .withAddress(listeningAddress)
                        .withManInTheMiddle(getMitmManager())
                        .withTransparent(true)
                        .withFiltersSource(new HttpProxyFiltersSourceImpl(context, database));

        Timber.d("Proxy server prepared");

        server = serverBootstrap.start();

        Timber.d("Proxy server started at address %s", server.getListenAddress().toString());
    }

    public void stop() {
        server.stop();
    }
}
