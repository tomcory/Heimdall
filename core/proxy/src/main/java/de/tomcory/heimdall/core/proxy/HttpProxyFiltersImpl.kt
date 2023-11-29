package de.tomcory.heimdall.core.proxy

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.system.OsConstants
import androidx.annotation.RequiresApi
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.proxy.littleshoot.HttpFiltersAdapter
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.http.FullHttpRequest
import io.netty.handler.codec.http.FullHttpResponse
import io.netty.handler.codec.http.HttpMethod
import io.netty.handler.codec.http.HttpObject
import io.netty.handler.codec.http.HttpRequest
import io.netty.handler.codec.http.HttpResponse
import io.netty.handler.codec.http.HttpUtil
import io.netty.util.AttributeKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber
import java.net.InetSocketAddress
import java.nio.charset.Charset
import java.util.Objects
import java.util.stream.Collectors

class HttpProxyFiltersImpl(
    originalRequest: HttpRequest?,
    ctx: ChannelHandlerContext,
    private val clientAddress: InetSocketAddress,
    private val httpCount: Long,
    private val context: Context
) : HttpFiltersAdapter(originalRequest, ctx) {
    private var isHttps = false
    private var connectedRemoteAddress: InetSocketAddress? = null
    private var aid = 0
    private var packageName = ""

    private val isHttpsAttrKey = AttributeKey.valueOf<Boolean>("isHttps")
    private val resolvedRemoteAddressKey = AttributeKey.valueOf<InetSocketAddress>("resolvedRemoteAddress")

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private suspend fun saveRequest(fhr: FullHttpRequest, currentResolved: InetSocketAddress, storeContent: Boolean = false) {

        // don't persist CONNECT requests
        if (fhr.method().name() == "CONNECT") {
            Timber.d("Ignoring CONNECT")
            return
        }

        // get the id of the app that initiated the request
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
        aid = cm?.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, clientAddress, ctx.channel().localAddress() as InetSocketAddress) ?: -1
        val pm = context.packageManager
        if (aid >= 0) {
            val packages = pm.getPackagesForUid(aid)
            if (packages != null) {
                packageName = packages[0]
            }
        }

        //wrap the access to the headers and content ByteBuf in try-catch blocks to prevent Netty weirdness
        val headers = try {
            fhr.headers().entries().stream()
                .map { (key, value): Map.Entry<String, String> -> "'" + key.replace('\'', '"') + "': '" + value.replace('\'', '"') + "'" }
                .collect(Collectors.joining(", ", "{", "}"))
        } catch (e: Exception) {
            Timber.w("Encountered Netty weirdness while accessing the request headers")
            ""
        }

        val content = try {
            if (storeContent) fhr.content().toString(Charset.defaultCharset()) else ""
        } catch (e: Exception) {
            Timber.w("Encountered Netty weirdness while accessing the request content")
            ""
        }

        val request = Request(
            timestamp = System.currentTimeMillis(),
            reqResId = httpCount.toInt(),
            headers = headers,
            content = content,
            contentLength = content.length,
            method = fhr.method().toString(),
            remoteHost = currentResolved.hostString,
            remotePath = if (fhr.uri().startsWith("/")) fhr.uri() else "",
            remoteIp = currentResolved.address.hostAddress ?: "",
            remotePort = currentResolved.port,
            localIp = clientAddress.address.hostAddress ?: "",
            localPort = clientAddress.port,
            initiatorId = aid,
            initiatorPkg = packageName
        )

        Timber.i("Inserting request into DB: aid=%s, pkg=%s, reqResId=%s, method=%s, host=%s", request.initiatorId, request.initiatorPkg, httpCount.toInt(), request.method, request.remoteHost)
        HeimdallDatabase.instance?.requestDao?.insert(request)
    }

    private suspend fun saveResponse(fhr: FullHttpResponse, currentResolved: InetSocketAddress, storeContent: Boolean = false) {

        //wrap the access to the headers and content ByteBuf in try-catch blocks to prevent Netty weirdness
        val headers = try {
            fhr.headers().entries().stream()
                .map { (key, value): Map.Entry<String, String> -> "'" + key.replace('\'', '"') + "': '" + value.replace('\'', '"') + "'" }
                .collect(Collectors.joining(", ", "{", "}"))
        } catch (e: Exception) {
            Timber.w("Encountered Netty weirdness while accessing the response headers")
            ""
        }

        val content = try {
            if (storeContent) fhr.content().toString(Charset.defaultCharset()) else ""
        } catch (e: Exception) {
            Timber.w("Encountered Netty weirdness while accessing the response content")
            ""
        }

        val response = Response(
            timestamp = System.currentTimeMillis(),
            reqResId = httpCount.toInt(),
            headers = headers,
            content = content,
            contentLength = content.length,
            statusCode = fhr.status().code(),
            statusMsg = fhr.status().reasonPhrase(),
            remoteHost = currentResolved.hostString,
            remoteIp = currentResolved.address.hostAddress ?: "",
            remotePort = currentResolved.port,
            localIp = clientAddress.address.hostAddress ?: "",
            localPort = clientAddress.port,
            initiatorId = aid,
            initiatorPkg = packageName
        )

        Timber.i("Inserting response into DB: aid=%s, pkg=%s, reqResId=%s, status=%s host=%s", response.initiatorId, response.initiatorPkg, httpCount.toInt(), response.statusCode, response.remoteHost)
        HeimdallDatabase.instance?.responseDao?.insert(response)
    }

    override fun clientToProxyRequest(httpObject: HttpObject): HttpResponse? {
        if (httpObject is HttpRequest) {
            val isHttpsAttr = ctx.attr(isHttpsAttrKey)
            var isHttpsVal = isHttpsAttr.get()
            if (Objects.isNull(isHttpsVal)) {
                isHttpsVal = false
            }
            if (httpObject.method() == HttpMethod.CONNECT) {
                isHttpsVal = true
            }
            isHttps = isHttpsVal
            isHttpsAttr.set(isHttpsVal)
            Timber.d("clientToProxyRequest: isHttps=%s method=%s, uri=%s, protocolVersion=%s",
                isHttps,
                httpObject.method(),
                httpObject.uri(),
                httpObject.protocolVersion()
            )
        }
        return null
    }

    override fun proxyToServerResolutionSucceeded(serverHostAndPort: String, resolvedRemoteAddress: InetSocketAddress) {
        Timber.d("proxyToServerResolutionSucceeded(%s, %s", serverHostAndPort, resolvedRemoteAddress)
        ctx.attr(resolvedRemoteAddressKey).set(resolvedRemoteAddress)
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    override fun proxyToServerRequest(httpObject: HttpObject): HttpResponse? {
        if (httpObject is FullHttpRequest) {
            CoroutineScope(Dispatchers.IO).launch {
                val currentResolved = ctx.attr(resolvedRemoteAddressKey).get()

                Timber.d("proxyToServerRequest: isHttps=%s method=%s, client=%s, remote=%s, url=%s",
                    isHttps,
                    httpObject.method().name(),
                    clientAddress,
                    currentResolved,
                    httpObject.uri()
                )

                // insert the request into the DB
                saveRequest(httpObject, currentResolved)
            }
        } else {
            Timber.e("proxyToServerRequest(): unexpected HttpObject (%s)", httpObject.javaClass)
        }
        return null
    }

    override fun proxyToServerConnectionStarted() {
        Timber.d("proxyToServerConnectionStarted()")
    }

    override fun proxyToServerConnectionSucceeded(serverCtx: ChannelHandlerContext) {
        connectedRemoteAddress = serverCtx.channel().remoteAddress() as InetSocketAddress
        Timber.d("proxyToServerConnectionSucceeded() to %s", connectedRemoteAddress)
    }

    override fun proxyToServerRequestSent() {
        Timber.d("proxyToServerRequestSent()")
    }

    override fun serverToProxyResponse(httpObject: HttpObject): HttpObject {
        Timber.d("serverToProxyResponse()")
        if (httpObject is FullHttpResponse) {
            CoroutineScope(Dispatchers.IO).launch {
                Timber.d("serverToProxyResponse(): %s %s %s, length=%s",
                    httpObject.protocolVersion().text(),
                    httpObject.status().code(),
                    httpObject.status().reasonPhrase(),
                    HttpUtil.getContentLength(httpObject, 0L)
                )

                // insert the response into the DB
                saveResponse(httpObject, ctx.attr(resolvedRemoteAddressKey).get())
            }
        }
        return httpObject
    }

    override fun proxyToClientResponse(httpObject: HttpObject): HttpObject {
        if (httpObject is FullHttpResponse) {
            Timber.d("proxyToClientResponse(): %s %s %s, length=%s",
                httpObject.protocolVersion().text(),
                httpObject.status().code(),
                httpObject.status().reasonPhrase(),
                HttpUtil.getContentLength(httpObject, 0L)
            )
        } else {
            Timber.e("proxyToClientResponse(): unexpected HttpObject (%s)", httpObject.javaClass)
        }
        return httpObject
    }

    override fun serverToProxyResponseReceived() {
        Timber.d("serverToProxyResponseReceived()")
    }
}