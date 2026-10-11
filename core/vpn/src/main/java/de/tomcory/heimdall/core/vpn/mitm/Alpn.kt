package de.tomcory.heimdall.core.vpn.mitm

import timber.log.Timber
import java.lang.reflect.Method
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLParameters

/**
 * Application-Layer Protocol Negotiation on an [SSLEngine].
 *
 * The API (`SSLParameters.setApplicationProtocols`, `SSLEngine.getApplicationProtocol`) exists on
 * Android from API 29 and on the JVM from Java 9. It is looked up by reflection rather than gated
 * on the SDK level, so that the same check holds on a device and in JVM unit tests; below API 29
 * [supported] is false and engines negotiate no ALPN, as before.
 */
object Alpn {

    /** The ALPN identifier of HTTP/1.1, the only application protocol the MitM can record. */
    const val HTTP_1_1 = "http/1.1"

    private val setApplicationProtocols: Method? = try {
        SSLParameters::class.java.getMethod("setApplicationProtocols", Array<String>::class.java)
    } catch (e: NoSuchMethodException) {
        null
    }

    private val getApplicationProtocol: Method? = try {
        SSLEngine::class.java.getMethod("getApplicationProtocol")
    } catch (e: NoSuchMethodException) {
        null
    }

    val supported: Boolean = setApplicationProtocols != null && getApplicationProtocol != null

    /**
     * Makes [engine] offer (client mode) or accept (server mode) [protocols]. Must be called
     * before the handshake begins. Does nothing for an empty list or without ALPN support.
     */
    fun offer(engine: SSLEngine, protocols: List<String>) {
        val setter = setApplicationProtocols ?: return
        if (protocols.isEmpty()) {
            return
        }
        try {
            val params = engine.sslParameters
            // passed as one argument, the String[] the method takes
            setter.invoke(params, protocols.toTypedArray())
            engine.sslParameters = params
        } catch (e: Exception) {
            Timber.w(e, "Could not set the application protocols $protocols")
        }
    }

    /** The protocol [engine] negotiated, or null if none was (or ALPN is not supported). */
    fun selected(engine: SSLEngine): String? {
        val getter = getApplicationProtocol ?: return null
        return try {
            (getter.invoke(engine) as String?)?.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Whether the MitM may intercept a client that offered [offered]: one that offers no ALPN, or
     * offers HTTP/1.1 among its protocols. A client that offers ALPN without HTTP/1.1 (gRPC, which
     * requires HTTP/2, or a non-HTTP protocol) would break on a connection that cannot give it what
     * it asked for.
     */
    fun interceptable(offered: List<String>): Boolean = offered.isEmpty() || HTTP_1_1 in offered
}
