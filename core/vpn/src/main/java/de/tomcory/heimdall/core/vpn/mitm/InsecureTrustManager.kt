package de.tomcory.heimdall.core.vpn.mitm

import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedTrustManager

/**
 * Trust manager that accepts every certificate chain without any validation. Only used for the
 * MitM engine's upstream (server-facing) connections, and only when the user explicitly enables
 * "Trust all upstream TLS certificates" (see [SSLEngineSource] and docs/vpn-mitm-audit.md PKT-07);
 * strict validation via [MergeTrustManager] is the default.
 *
 * This deliberately extends [X509ExtendedTrustManager] rather than implementing the plain
 * [javax.net.ssl.X509TrustManager]: JSSE wraps a plain X509TrustManager in its internal
 * AbstractTrustManagerWrapper, which re-applies endpoint identification and algorithm-constraint
 * checks on top of it. Since [SSLEngineSource.newSSLEngine] enables "HTTPS" endpoint
 * identification, a plain implementation would still reject hostname mismatches - i.e. it wouldn't
 * actually trust all certificates. Replaces Netty's InsecureTrustManagerFactory
 * (docs/vpn-mitm-audit.md PKT-20).
 */
object InsecureTrustManager : X509ExtendedTrustManager() {

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {}

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {}

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {}

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {}

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
