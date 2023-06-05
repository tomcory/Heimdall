package proxy;

import android.content.Context;

import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.HttpProxyServerBootstrap;
import org.littleshoot.proxy.SelectiveMitmManagerAdapter;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.mitm.CertificateSniffingMitmManager;

import java.net.InetSocketAddress;

import timber.log.Timber;

public class HeimdallHttpProxyServer {

    private final InetSocketAddress listeningAddress;
    private CertificateSniffingMitmManager mitmManager;
    private final Context context;

    private HttpProxyServer server;

    public HeimdallHttpProxyServer(final InetSocketAddress listeningAddress, CertificateSniffingMitmManager mitmManager, Context applicationContext) {
        this.listeningAddress = listeningAddress;
        this.context = applicationContext;

        if (mitmManager != null) {
            this.mitmManager = mitmManager;
        }
    }

    private SelectiveMitmManagerAdapter getMitmManager() {
        return new SelectiveMitmManagerAdapter(mitmManager) {
            @Override
            public boolean shouldMITMPeer(String peerHost, int peerPort) {
                if (whiteLsited.contains(peerHost + peerPort)) {
                    removeWhiteListed(peerHost + peerHost);
                    return false;
                }
                // HostAndPort.fromParts(peerHost, peerPort);
                return true;
            }

            @Override
            public void addWhiteListed(String hostAndPort) {
                whiteLsited.add(hostAndPort);
            }

            @Override
            public void removeWhiteListed(String hostAndPort) {
                whiteLsited.remove(hostAndPort);
            }
        };
    }

    public void start() {
        HttpProxyServerBootstrap serverBootstrap = DefaultHttpProxyServer
                        .bootstrap()
                        .withAddress(listeningAddress)
                        .withManInTheMiddle(getMitmManager())
                        .withTransparent(true)
                        .withFiltersSource(new HttpProxyFiltersSourceImpl(context));

        Timber.d("Proxy server prepared");

        server = serverBootstrap.start();

        Timber.d("Proxy server started at address %s", server.getListenAddress().toString());
    }

    public void stop() {
        server.stop();
    }
}
