package de.tomcory.heimdall.core.proxy;

import android.content.Context;

import java.net.InetSocketAddress;

import de.tomcory.heimdall.core.database.HeimdallDatabase;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpFilters;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpFiltersSourceAdapter;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpRequest;

public class HttpProxyFiltersSourceImpl extends HttpFiltersSourceAdapter {

    private final Context context;
    private final HeimdallDatabase database;

    private final int sessionId;

    public HttpProxyFiltersSourceImpl(Context context, HeimdallDatabase database, int sessionId) {
        this.context = context;
        this.database = database;
        this.sessionId = sessionId;
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext ctx) {

        return new HttpProxyFiltersImpl(
            originalRequest,
            ctx,
            (InetSocketAddress) ctx.channel().remoteAddress(), context, database, sessionId);
    }

    @Override
    public int getMaximumRequestBufferSizeInBytes() {
        return 10 * 1024 * 1024; // aggregate chunks and decompress until 10MB request.
    }

    @Override
    public int getMaximumResponseBufferSizeInBytes() {
        return 10 * 1024 * 1024; // aggregate chunks and decompress until 10MB response.
    }

}
