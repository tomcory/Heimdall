package de.tomcory.heimdall.core.export.jsonl

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * What a capture session was configured to do, as it was resolved when the session started: the stored
 * preferences with the session's own options applied. An export's manifest carries it, so that an
 * analysis knows what the capture could and could not observe.
 *
 * @param mitm Whether TLS was decrypted.
 * @param includedApps If not null, the only packages whose TLS was decrypted.
 * @param hostMode How [hosts] limited decryption: ALL, WHITELIST or BLACKLIST.
 * @param quicPolicy What was done with QUIC while MitM was on: PASSTHROUGH or BLOCK.
 * @param blockedHosts Hosts whose connections were dropped.
 * @param maxHttpBodyBytes Bodies longer than this were stored truncated.
 * @param privateDnsStrict Whether the device's Private DNS was in strict mode; otherwise DNS over TLS to
 * the VPN's DNS server was refused, so that DNS went through Heimdall's cache.
 * @param apps The packages whose traffic the session routed through the VPN; empty for all.
 */
data class CaptureSettings(
    val mitm: Boolean,
    val includedApps: Set<String>?,
    val excludedApps: Set<String>,
    val hostMode: String,
    val hosts: List<String>,
    val learnPassthrough: Boolean,
    val trustAllUpstreamCertificates: Boolean,
    val quicPolicy: String,
    val blockedHosts: List<String>,
    val maxHttpBodyBytes: Int,
    val privateDnsStrict: Boolean,
    val apps: List<String>
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("mitm", mitm)
        put("mitm_scope", buildJsonObject {
            put("included_apps", includedApps?.let { strings(it.sorted()) } ?: JsonNull)
            put("excluded_apps", strings(excludedApps.sorted()))
            put("host_mode", hostMode.lowercase())
            put("hosts", strings(hosts))
        })
        // the MitM engine offers only http/1.1 to both sides, so that every decrypted request is recorded
        put("alpn_http1_only", mitm)
        put("learn_passthrough", learnPassthrough)
        put("trust_all_upstream_certificates", trustAllUpstreamCertificates)
        put("quic_policy", quicPolicy.lowercase())
        put("blocked_hosts", strings(blockedHosts))
        put("max_http_body_bytes", maxHttpBodyBytes)
        put("private_dns", if (privateDnsStrict) "strict" else "dot_to_vpn_dns_refused")
        put("apps", strings(apps))
    }

    private fun strings(values: List<String>) = JsonArray(values.map { JsonPrimitive(it) })
}
