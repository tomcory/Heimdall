package de.tomcory.heimdall.core.proxy;

import java.nio.charset.StandardCharsets;
import java.util.Map.Entry;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpRequestEncoder;
import io.netty.handler.codec.http.HttpResponseDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;

public class NettyUtil {

    private NettyUtil() {
        throw new AssertionError("Java Rationale: Utility class prohibits Instantiation.");
    }

    private final static int MAX_INITIAL_LINE_LENGTH = 10 * 1024 * 1024;
    private final static int MAX_HEADER_SIZE = 10 * 1024 * 1024;
    private final static int MAX_CHUNK_SIZE = 10 * 1024 * 1024;
    private final static int MAX_CONTENT_LENGTH = 10 * 1024 * 1024;


    public static FullHttpRequest BytesToFullHttpRequest(byte[] src) {
        HttpRequestDecoder dec =
            new HttpRequestDecoder(MAX_INITIAL_LINE_LENGTH, MAX_HEADER_SIZE, MAX_CHUNK_SIZE, false);
        HttpObjectAggregator aggr = new HttpObjectAggregator(MAX_CONTENT_LENGTH);
        EmbeddedChannel ch = new EmbeddedChannel(dec, aggr);
        ch.writeInbound(Unpooled.copiedBuffer(src));
        ch.finish();
        FullHttpRequest fhr = (FullHttpRequest) ch.readInbound();
        ch.close();
        return fhr;
    }

    public static byte[] FullHttpRequestToBytes(FullHttpRequest fhr) {
        StringBuilder headersb = new StringBuilder(8 * 1024);
        headersb.append(fhr.getMethod().name());
        headersb.append(" ");
        headersb.append(fhr.getUri());
        headersb.append(" ");
        headersb.append(fhr.getProtocolVersion().text());
        headersb.append("\r\n");
        HttpHeaders headers = fhr.headers();
        for (Entry<String, String> header : headers) {
            headersb.append(header.getKey());
            headersb.append(": ");
            headersb.append(header.getValue());
            headersb.append("\r\n");
        }
        headersb.append("\r\n");
        ByteBuf bb = Unpooled.buffer();
        bb.writeBytes(headersb.toString().getBytes(StandardCharsets.UTF_8));

        ByteBuf body = fhr.content();
        byte[] bodyBytes = new byte[body.readableBytes()];
        body.readBytes(bodyBytes);
        body.release();

        bb.writeBytes(bodyBytes);
        byte[] finalBytes = new byte[bb.readableBytes()];
        bb.readBytes(finalBytes);
        return finalBytes;
    }


    @Deprecated
    public static byte[] depreFullHttpRequestToBytes(FullHttpRequest fhr) {
        HttpRequestEncoder enc = new HttpRequestEncoder();
        HttpObjectAggregator aggr = new HttpObjectAggregator(MAX_CONTENT_LENGTH);
        EmbeddedChannel ch = new EmbeddedChannel(enc, aggr);
        ch.writeOutbound(fhr);
        ch.flush();
        ByteBuf encoded = (ByteBuf) ch.readOutbound();
        byte[] bytes = new byte[encoded.readableBytes()];
        encoded.readBytes(bytes);
        encoded.release();
        ch.close();
        return bytes;
    }

    public static FullHttpResponse BytesToFullHttpResponse(byte[] src) {
        HttpResponseDecoder dec =
            new HttpResponseDecoder(MAX_INITIAL_LINE_LENGTH, MAX_HEADER_SIZE, MAX_CHUNK_SIZE, false);
        HttpObjectAggregator aggr = new HttpObjectAggregator(MAX_CONTENT_LENGTH);
        EmbeddedChannel ch = new EmbeddedChannel(dec, aggr);
        ch.writeInbound(Unpooled.copiedBuffer(src));
        ch.finish();
        FullHttpResponse fhr = (FullHttpResponse) ch.readInbound();
        ch.close();
        return fhr;
    }


    public static byte[] FullHttpResponseToBytes(FullHttpResponse fhr) {
        StringBuilder headersb = new StringBuilder(8 * 1024);
        headersb.append(fhr.getProtocolVersion().text());
        headersb.append(" ");
        headersb.append(fhr.getStatus().code());
        headersb.append(" ");
        headersb.append(fhr.getStatus().reasonPhrase());
        headersb.append("\r\n");
        HttpHeaders headers = fhr.headers();
        for (Entry<String, String> header : headers) {
            headersb.append(header.getKey());
            headersb.append(": ");
            headersb.append(header.getValue());
            headersb.append("\r\n");
        }
        headersb.append("\r\n");
        ByteBuf bb = Unpooled.buffer();
        bb.writeBytes(headersb.toString().getBytes(StandardCharsets.UTF_8));

        ByteBuf body = fhr.content();
        byte[] bodyBytes = new byte[body.readableBytes()];
        body.readBytes(bodyBytes);
        body.release();

        bb.writeBytes(bodyBytes);
        byte[] finalBytes = new byte[bb.readableBytes()];
        bb.readBytes(finalBytes);
        return finalBytes;
    }

    @Deprecated
    public static byte[] depreFullHttpResponseToBytes(FullHttpResponse fhr) {
        HttpResponseEncoder enc = new HttpResponseEncoder();
        HttpObjectAggregator aggr = new HttpObjectAggregator(MAX_CONTENT_LENGTH);
        EmbeddedChannel ch = new EmbeddedChannel(enc, aggr);
        ch.writeOutbound(fhr);
        ch.flush();
        ByteBuf encoded = (ByteBuf) ch.readOutbound();
        byte[] bytes = new byte[encoded.readableBytes()];
        encoded.readBytes(bytes);
        encoded.release();
        ch.close();
        return bytes;
    }
}
