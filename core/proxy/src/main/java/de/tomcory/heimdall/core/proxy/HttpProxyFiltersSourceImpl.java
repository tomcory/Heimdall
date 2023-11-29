package de.tomcory.heimdall.core.proxy;

import android.content.Context;

import java.net.InetSocketAddress;

import de.tomcory.heimdall.core.proxy.littleshoot.HttpFilters;
import de.tomcory.heimdall.core.proxy.littleshoot.HttpFiltersSourceAdapter;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpRequest;

public class HttpProxyFiltersSourceImpl extends HttpFiltersSourceAdapter {


    private long httpCount = 0L;
    private Context context;

    public HttpProxyFiltersSourceImpl(Context context) {
        this.context = context;
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext ctx) {

        httpCount++;
        return new HttpProxyFiltersImpl(
            originalRequest,
            ctx,
            (InetSocketAddress) ctx.channel().remoteAddress(),
            httpCount, context);
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
