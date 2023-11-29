package de.tomcory.heimdall.core.proxy.littleshoot.impl;

import de.tomcory.heimdall.core.proxy.littleshoot.ActivityTracker;
import de.tomcory.heimdall.core.proxy.littleshoot.ChainedProxyManager;
import de.tomcory.heimdall.core.proxy.littleshoot.DefaultHostResolver;
import de.tomcory.heimdall.core.proxy.littleshoot.DnsSecServerResolver;
import de.tomcory.heimdall.core.proxy.littleshoot.HostResolver;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpFiltersSource;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpFiltersSourceAdapter;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpProxyServer;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpProxyServerBootstrap;
import de.tomcory.heimdall.core.proxy.littleshoot.MitmManager;
import de.tomcory.heimdall.core.proxy.littleshoot.ProxyAuthenticator;
import de.tomcory.heimdall.core.proxy.littleshoot.SslEngineSource;
import de.tomcory.heimdall.core.proxy.littleshoot.TransportProtocol;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Properties;
import java.util.concurrent.ConcurrentLinkedQueue;

import timber.log.Timber;

public class DefaultHttpProxyServerBootstrap implements HttpProxyServerBootstrap {

    private static final int MAX_INITIAL_LINE_LENGTH_DEFAULT = 8192;
    private static final int MAX_HEADER_SIZE_DEFAULT = 8192*2;
    private static final int MAX_CHUNK_SIZE_DEFAULT = 8192*2;

    private String name = "LittleProxy";
    private ServerGroup serverGroup = null;
    private TransportProtocol transportProtocol = TransportProtocol.TCP;
    private InetSocketAddress requestedAddress;
    private int port = 8080;
    private boolean allowLocalOnly = true;
    private SslEngineSource sslEngineSource = null;
    private boolean authenticateSslClients = true;
    private ProxyAuthenticator proxyAuthenticator = null;
    private ChainedProxyManager chainProxyManager = null;
    private MitmManager mitmManager = null;
    private HttpFiltersSource filtersSource = new HttpFiltersSourceAdapter();
    private boolean transparent = false;
    private int idleConnectionTimeout = 70;
    private Collection<ActivityTracker> activityTrackers = new ConcurrentLinkedQueue<ActivityTracker>();
    private int connectTimeout = 40000;
    private HostResolver serverResolver = new DefaultHostResolver();
    private long readThrottleBytesPerSecond;
    private long writeThrottleBytesPerSecond;
    private InetSocketAddress localAddress;
    private String proxyAlias;
    private int clientToProxyAcceptorThreads = ServerGroup.DEFAULT_INCOMING_ACCEPTOR_THREADS;
    private int clientToProxyWorkerThreads = ServerGroup.DEFAULT_INCOMING_WORKER_THREADS;
    private int proxyToServerWorkerThreads = ServerGroup.DEFAULT_OUTGOING_WORKER_THREADS;
    private int maxInitialLineLength = MAX_INITIAL_LINE_LENGTH_DEFAULT;
    private int maxHeaderSize = MAX_HEADER_SIZE_DEFAULT;
    private int maxChunkSize = MAX_CHUNK_SIZE_DEFAULT;
    private boolean allowRequestToOriginServer = false;

    DefaultHttpProxyServerBootstrap() {
    }

    DefaultHttpProxyServerBootstrap(
            ServerGroup serverGroup,
            TransportProtocol transportProtocol,
            InetSocketAddress requestedAddress,
            SslEngineSource sslEngineSource,
            boolean authenticateSslClients,
            ProxyAuthenticator proxyAuthenticator,
            ChainedProxyManager chainProxyManager,
            MitmManager mitmManager,
            HttpFiltersSource filtersSource,
            boolean transparent, int idleConnectionTimeout,
            Collection<ActivityTracker> activityTrackers,
            int connectTimeout, HostResolver serverResolver,
            long readThrottleBytesPerSecond,
            long writeThrottleBytesPerSecond,
            InetSocketAddress localAddress,
            String proxyAlias,
            int maxInitialLineLength,
            int maxHeaderSize,
            int maxChunkSize,
            boolean allowRequestToOriginServer) {
        this.serverGroup = serverGroup;
        this.transportProtocol = transportProtocol;
        this.requestedAddress = requestedAddress;
        this.port = requestedAddress.getPort();
        this.sslEngineSource = sslEngineSource;
        this.authenticateSslClients = authenticateSslClients;
        this.proxyAuthenticator = proxyAuthenticator;
        this.chainProxyManager = chainProxyManager;
        this.mitmManager = mitmManager;
        this.filtersSource = filtersSource;
        this.transparent = transparent;
        this.idleConnectionTimeout = idleConnectionTimeout;
        if (activityTrackers != null) {
            this.activityTrackers.addAll(activityTrackers);
        }
        this.connectTimeout = connectTimeout;
        this.serverResolver = serverResolver;
        this.readThrottleBytesPerSecond = readThrottleBytesPerSecond;
        this.writeThrottleBytesPerSecond = writeThrottleBytesPerSecond;
        this.localAddress = localAddress;
        this.proxyAlias = proxyAlias;
        this.maxInitialLineLength = maxInitialLineLength;
        this.maxHeaderSize = maxHeaderSize;
        this.maxChunkSize = maxChunkSize;
        this.allowRequestToOriginServer = allowRequestToOriginServer;
    }

    DefaultHttpProxyServerBootstrap(Properties props) {
        this.withUseDnsSec(ProxyUtils.extractBooleanDefaultFalse(
                props, "dnssec"));
        this.transparent = ProxyUtils.extractBooleanDefaultFalse(
                props, "transparent");
        this.idleConnectionTimeout = ProxyUtils.extractInt(props,
                "idle_connection_timeout");
        this.connectTimeout = ProxyUtils.extractInt(props,
                "connect_timeout", 0);
        this.maxInitialLineLength = ProxyUtils.extractInt(props,
                "max_initial_line_length", MAX_INITIAL_LINE_LENGTH_DEFAULT);
        this.maxHeaderSize = ProxyUtils.extractInt(props,
                "max_header_size", MAX_HEADER_SIZE_DEFAULT);
        this.maxChunkSize = ProxyUtils.extractInt(props,
                "max_chunk_size", MAX_CHUNK_SIZE_DEFAULT);
    }

    @Override
    public HttpProxyServerBootstrap withName(String name) {
        this.name = name;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTransportProtocol(
            TransportProtocol transportProtocol) {
        this.transportProtocol = transportProtocol;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAddress(InetSocketAddress address) {
        this.requestedAddress = address;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withPort(int port) {
        this.requestedAddress = null;
        this.port = port;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withNetworkInterface(InetSocketAddress inetSocketAddress) {
        this.localAddress = inetSocketAddress;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withProxyAlias(String alias) {
        this.proxyAlias = alias;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAllowLocalOnly(
            boolean allowLocalOnly) {
        this.allowLocalOnly = allowLocalOnly;
        return this;
    }

    @Override
    @Deprecated
    public HttpProxyServerBootstrap withListenOnAllAddresses(boolean listenOnAllAddresses) {
        Timber.w("withListenOnAllAddresses() is deprecated and will be removed in a future release. Use withNetworkInterface().");
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withSslEngineSource(
            SslEngineSource sslEngineSource) {
        this.sslEngineSource = sslEngineSource;
        if (this.mitmManager != null) {
            Timber.w("Enabled encrypted inbound connections with man in the middle. "
                    + "These are mutually exclusive - man in the middle will be disabled.");
            this.mitmManager = null;
        }
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAuthenticateSslClients(
            boolean authenticateSslClients) {
        this.authenticateSslClients = authenticateSslClients;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withProxyAuthenticator(
            ProxyAuthenticator proxyAuthenticator) {
        this.proxyAuthenticator = proxyAuthenticator;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withChainProxyManager(
            ChainedProxyManager chainProxyManager) {
        this.chainProxyManager = chainProxyManager;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withManInTheMiddle(
            MitmManager mitmManager) {
        this.mitmManager = mitmManager;
        if (this.sslEngineSource != null) {
            Timber.w("Enabled man in the middle with encrypted inbound connections. "
                    + "These are mutually exclusive - encrypted inbound connections will be disabled.");
            this.sslEngineSource = null;
        }
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withFiltersSource(
            HttpFiltersSource filtersSource) {
        this.filtersSource = filtersSource;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withUseDnsSec(boolean useDnsSec) {
        if (useDnsSec) {
            this.serverResolver = new DnsSecServerResolver();
        } else {
            this.serverResolver = new DefaultHostResolver();
        }
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTransparent(
            boolean transparent) {
        this.transparent = transparent;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withIdleConnectionTimeout(
            int idleConnectionTimeout) {
        this.idleConnectionTimeout = idleConnectionTimeout;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withConnectTimeout(
            int connectTimeout) {
        this.connectTimeout = connectTimeout;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withServerResolver(
            HostResolver serverResolver) {
        this.serverResolver = serverResolver;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap plusActivityTracker(
            ActivityTracker activityTracker) {
        activityTrackers.add(activityTracker);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withThrottling(long readThrottleBytesPerSecond, long writeThrottleBytesPerSecond) {
        this.readThrottleBytesPerSecond = readThrottleBytesPerSecond;
        this.writeThrottleBytesPerSecond = writeThrottleBytesPerSecond;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxInitialLineLength(int maxInitialLineLength){
        this.maxInitialLineLength = maxInitialLineLength;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxHeaderSize(int maxHeaderSize){
        this.maxHeaderSize = maxHeaderSize;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxChunkSize(int maxChunkSize){
        this.maxChunkSize = maxChunkSize;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAllowRequestToOriginServer(boolean allowRequestToOriginServer) {
        this.allowRequestToOriginServer = allowRequestToOriginServer;
        return this;
    }

    @Override
    public HttpProxyServer start() {
        return build().start();
    }

    @Override
    public HttpProxyServerBootstrap withThreadPoolConfiguration(ThreadPoolConfiguration configuration) {
        this.clientToProxyAcceptorThreads = configuration.getAcceptorThreads();
        this.clientToProxyWorkerThreads = configuration.getClientToProxyWorkerThreads();
        this.proxyToServerWorkerThreads = configuration.getProxyToServerWorkerThreads();
        return this;
    }

    private DefaultHttpProxyServer build() {
        final ServerGroup serverGroup;

        if (this.serverGroup != null) {
            serverGroup = this.serverGroup;
        }
        else {
            serverGroup = new ServerGroup(name, clientToProxyAcceptorThreads, clientToProxyWorkerThreads, proxyToServerWorkerThreads);
        }

        return new DefaultHttpProxyServer(serverGroup,
                transportProtocol, determineListenAddress(),
                sslEngineSource, authenticateSslClients,
                proxyAuthenticator, chainProxyManager, mitmManager,
                filtersSource, transparent,
                idleConnectionTimeout, activityTrackers, connectTimeout,
                serverResolver, readThrottleBytesPerSecond, writeThrottleBytesPerSecond,
                localAddress, proxyAlias, maxInitialLineLength, maxHeaderSize, maxChunkSize,
                allowRequestToOriginServer);
    }

    private InetSocketAddress determineListenAddress() {
        if (requestedAddress != null) {
            return requestedAddress;
        } else {
            // Binding only to localhost can significantly improve the
            // security of the proxy.
            if (allowLocalOnly) {
                return new InetSocketAddress("127.0.0.1", port);
            } else {
                return new InetSocketAddress(port);
            }
        }
    }
}
