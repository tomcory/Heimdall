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

    public HttpProxyFiltersSourceImpl(Context context, HeimdallDatabase database) {
        this.context = context;
        this.database = database;
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext ctx) {

        return new HttpProxyFiltersImpl(
            originalRequest,
            ctx,
            (InetSocketAddress) ctx.channel().remoteAddress(), context, database);
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
