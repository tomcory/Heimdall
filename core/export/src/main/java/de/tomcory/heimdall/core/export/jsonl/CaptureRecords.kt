package de.tomcory.heimdall.core.export.jsonl

import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.export.util.bodyAsText
import de.tomcory.heimdall.core.export.util.headerPairs
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The records of a capture export, one JSON object per line.
 *
 * A message record carries the request under `http_request`, with `method`, `path`, `headers`
 * as a list of `{key, value}` and `body`: the form in which the other Asgard components read an
 * HTTP message. Everything else a capture knows is added around it.
 */
object CaptureRecords {

    /** Name written into every record's `capture.backend`. */
    const val BACKEND = "heimdall"

    /**
     * @param response The request's response, or null if none was recorded.
     * @param session The connection's session, or null if its row is gone.
     * @param version Heimdall's version name.
     */
    fun message(request: Request, response: Response?, connection: Connection, session: Session?, version: String): JsonObject {
        val (requestEncoding, requestBody) = bodyAsText(request.headers, request.content)
        return buildJsonObject {
            put("id", "${connection.sessionId}-${request.id}")
            put("time", buildJsonObject {
                put("start", request.timestamp)
                put("end", response?.timestamp)
            })
            put("app", app(connection))
            put("http_request", buildJsonObject {
                put("method", request.method)
                put("scheme", if (connection.securityProtocol == SecurityProtocol.TLS) "https" else "http")
                put("host", request.remoteHost)
                put("port", request.remotePort)
                put("path", request.remotePath)
                put("headers", headers(request.headers))
                put("body", requestBody)
                put("body_encoding", requestEncoding)
                put("body_truncated", request.contentTruncated)
                put("content_length", request.contentLength)
            })
            if (response == null) {
                put("http_response", JsonNull)
            } else {
                val (responseEncoding, responseBody) = bodyAsText(response.headers, response.content)
                put("http_response", buildJsonObject {
                    put("status", response.statusCode)
                    put("message", response.statusMsg)
                    put("headers", headers(response.headers))
                    put("body", responseBody)
                    put("body_encoding", responseEncoding)
                    put("body_truncated", response.contentTruncated)
                    put("content_length", response.contentLength)
                })
            }
            put("connection", buildJsonObject {
                put("id", connection.id)
                put("remote_ip", connection.remoteIp)
                put("remote_port", connection.remotePort)
                put("local_port", connection.localPort)
                put("security", connection.securityProtocol?.name)
                put("sni", connection.sni)
                put("alpn", connection.alpn)
                put("is_tracker", connection.isTracker)
            })
            put("capture", capture(connection, session, version))
            put("blocked", connection.blocked)
        }
    }

    /** One connection, whether or not its traffic was decrypted. */
    fun connection(connection: Connection, session: Session?, version: String): JsonObject = buildJsonObject {
        put("id", "${connection.sessionId}-c${connection.id}")
        put("time", buildJsonObject { put("start", connection.initialTimestamp) })
        put("app", app(connection))
        put("protocol", connection.protocol.name)
        put("ip_version", connection.ipVersion)
        put("security", connection.securityProtocol?.name)
        put("host", connection.remoteHost)
        put("sni", connection.sni)
        put("alpn", connection.alpn)
        put("ech_offered", connection.echOffered)
        put("remote_ip", connection.remoteIp)
        put("remote_port", connection.remotePort)
        put("local_port", connection.localPort)
        put("bytes_out", connection.bytesOut)
        put("bytes_in", connection.bytesIn)
        put("is_tracker", connection.isTracker)
        put("blocked", connection.blocked)
        put("block_reason", connection.blockReason)
        put("passthrough_reason", connection.passthroughReason)
        put("capture", capture(connection, session, version))
    }

    private fun app(connection: Connection) = buildJsonObject {
        put("package", connection.initiatorPkg)
        put("uid", connection.initiatorId)
    }

    private fun capture(connection: Connection, session: Session?, version: String) = buildJsonObject {
        put("backend", BACKEND)
        put("version", version)
        put("session", connection.sessionId)
        put("tag", session?.tag)
    }

    private fun headers(stored: String): JsonArray = buildJsonArray {
        headerPairs(stored).forEach { (name, value) ->
            add(buildJsonObject {
                put("key", name)
                put("value", value)
            })
        }
    }
}
