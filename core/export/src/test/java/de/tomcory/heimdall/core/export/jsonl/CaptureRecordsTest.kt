package de.tomcory.heimdall.core.export.jsonl

import de.tomcory.heimdall.core.database.entity.Connection
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.database.entity.SecurityProtocol
import de.tomcory.heimdall.core.database.entity.Session
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureRecordsTest {

    private val session = Session(id = 12, startTime = 1000, endTime = 2000, tag = "baseline-1")

    private fun connection(
        security: SecurityProtocol? = SecurityProtocol.TLS, blocked: Boolean = false, blockReason: String? = null
    ) = Connection(
        id = 48, sessionId = 12, protocol = Protocol.TCP, ipVersion = 4, initialTimestamp = 1100,
        initiatorId = 10180, initiatorPkg = "com.example.app", localPort = 40000,
        remoteHost = "api.example.com", remoteIp = "93.184.216.34", remotePort = 443, isTracker = true,
        bytesOut = 512, bytesIn = 2048, securityProtocol = security, sni = "api.example.com", alpn = "http/1.1",
        blocked = blocked, blockReason = blockReason
    )

    private fun request(body: ByteArray = """{"email":"jane@example.org"}""".toByteArray(), truncated: Boolean = false) = Request(
        id = 131, connectionId = 48, timestamp = 1200,
        headers = "Host: api.example.com\nContent-Type: application/json",
        content = body, contentLength = body.size, contentTruncated = truncated,
        method = "POST", remoteHost = "api.example.com", remotePath = "/v1/signup?ref=a",
        remoteIp = "93.184.216.34", remotePort = 443, localIp = "10.120.0.1", localPort = 40000,
        initiatorId = 10180, initiatorPkg = "com.example.app"
    )

    private val response = Response(
        id = 7, requestId = 131, timestamp = 1300, headers = "Content-Type: image/png",
        content = byteArrayOf(1, 2, 3), contentLength = 3, statusCode = 200, statusMsg = "OK",
        remoteHost = "api.example.com", remoteIp = "93.184.216.34", remotePort = 443,
        localIp = "10.120.0.1", localPort = 40000, initiatorId = 10180, initiatorPkg = "com.example.app"
    )

    private fun JsonObject.obj(key: String) = getValue(key).jsonObject
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content

    @Test
    fun `a message carries the request where an HTTP message is read from`() {
        val record = CaptureRecords.message(request(), response, connection(), session, "0.1")
        val http = record.obj("http_request")

        assertEquals("12-131", record.text("id"))
        assertEquals("POST", http.text("method"))
        assertEquals("https", http.text("scheme"))
        assertEquals("api.example.com", http.text("host"))
        assertEquals(443, http.getValue("port").jsonPrimitive.int)
        assertEquals("/v1/signup?ref=a", http.text("path"))
        assertEquals("""{"email":"jane@example.org"}""", String(Base64.getDecoder().decode(http.text("body"))))
        assertEquals("base64", http.text("body_encoding"))
        assertFalse(http.getValue("body_truncated").jsonPrimitive.boolean)
        val headers = http.getValue("headers").jsonArray.map { it.jsonObject.text("key") to it.jsonObject.text("value") }
        assertEquals(listOf("Host" to "api.example.com", "Content-Type" to "application/json"), headers)
    }

    @Test
    fun `a message names its app, connection, session and tag`() {
        val record = CaptureRecords.message(request(), response, connection(), session, "0.1")

        assertEquals("com.example.app", record.obj("app").text("package"))
        assertEquals(10180, record.obj("app").getValue("uid").jsonPrimitive.int)
        assertEquals(48, record.obj("connection").getValue("id").jsonPrimitive.long)
        assertTrue(record.obj("connection").getValue("is_tracker").jsonPrimitive.boolean)
        assertEquals("heimdall", record.obj("capture").text("backend"))
        assertEquals(12, record.obj("capture").getValue("session").jsonPrimitive.long)
        assertEquals("baseline-1", record.obj("capture").text("tag"))
        assertEquals(1200, record.obj("time").getValue("start").jsonPrimitive.long)
        assertEquals(1300, record.obj("time").getValue("end").jsonPrimitive.long)
        assertFalse(record.getValue("blocked").jsonPrimitive.boolean)
    }

    @Test
    fun `a compressed body with a textual content type keeps its bytes`() {
        val gzip = byteArrayOf(0x1f, 0x8b.toByte(), 0x08, 0x00, 0xff.toByte(), 0x00, 0x0a, 0x22)
        val http = CaptureRecords.message(
            request().copy(headers = "Content-Type: application/json\nContent-Encoding: gzip", content = gzip),
            null, connection(), session, "0.1"
        ).obj("http_request")
        assertEquals("base64", http.text("body_encoding"))
        assertArrayEquals(gzip, java.util.Base64.getDecoder().decode(http.text("body")))
    }

    @Test
    fun `an empty body is an empty string`() {
        val http = CaptureRecords.message(request().copy(content = ByteArray(0)), null, connection(), session, "0.1").obj("http_request")
        assertEquals("", http.text("body"))
        assertEquals("base64", http.text("body_encoding"))
    }

    @Test
    fun `a response body is Base64, a missing response is null`() {
        val withResponse = CaptureRecords.message(request(), response, connection(), session, "0.1").obj("http_response")
        assertEquals(200, withResponse.getValue("status").jsonPrimitive.int)
        assertEquals("base64", withResponse.text("body_encoding"))
        assertEquals("AQID", withResponse.text("body"))

        val without = CaptureRecords.message(request(), null, connection(), session, "0.1")
        assertEquals(JsonNull, without.getValue("http_response"))
        assertEquals(JsonNull, without.obj("time").getValue("end"))
    }

    @Test
    fun `plain connections are http, truncated bodies say so, a lost session leaves the tag empty`() {
        val record = CaptureRecords.message(request(truncated = true), null, connection(security = SecurityProtocol.PLAIN), null, "0.1")
        assertEquals("http", record.obj("http_request").text("scheme"))
        assertTrue(record.obj("http_request").getValue("body_truncated").jsonPrimitive.boolean)
        assertEquals(JsonNull, record.obj("capture").getValue("tag"))
    }

    @Test
    fun `a connection record says whether and why it was blocked`() {
        val record = CaptureRecords.connection(connection(blocked = true, blockReason = "host_rule"), session, "0.1")

        assertEquals("12-c48", record.text("id"))
        assertEquals("TCP", record.text("protocol"))
        assertEquals("TLS", record.text("security"))
        assertEquals("api.example.com", record.text("host"))
        assertEquals(512, record.getValue("bytes_out").jsonPrimitive.long)
        assertTrue(record.getValue("blocked").jsonPrimitive.boolean)
        assertEquals("host_rule", record.text("block_reason"))
        assertEquals(JsonNull, record.getValue("passthrough_reason"))
        assertEquals("baseline-1", record.obj("capture").text("tag"))
    }

    @Test
    fun `every record is one line of valid JSON`() {
        val body = "line one\nline \"two\"\r\n\ttab ü €".toByteArray()
        val line = CaptureRecords.message(request(body = body), response, connection(), session, "0.1").toString()

        assertFalse(line.contains('\n'))
        val parsed = Json.parseToJsonElement(line).jsonObject
        assertArrayEquals(body, java.util.Base64.getDecoder().decode(parsed.obj("http_request").text("body")))
    }
}
