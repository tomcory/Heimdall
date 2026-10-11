package de.tomcory.heimdall.core.export.csv

import de.tomcory.heimdall.core.database.dao.RequestWithConnectionIsTracker
import org.junit.Assert.assertEquals
import org.junit.Test

/** Tests for docs/records/vpn-mitm-audit.md PKT-59. */
class CsvExportTest {

    @Test
    fun `a textual body is exported as text`() {
        val (encoding, text) = bodyForCsv("Host: a\nContent-Type: application/json; charset=utf-8", """{"a":"ä"}""".toByteArray())
        assertEquals("text", encoding)
        assertEquals("""{"a":"ä"}""", text)
    }

    @Test
    fun `a binary body is exported as Base64`() {
        val bytes = ByteArray(256) { it.toByte() }
        val (encoding, text) = bodyForCsv("Content-Type: image/png", bytes)
        assertEquals("base64", encoding)
        assertEquals(java.util.Base64.getEncoder().encodeToString(bytes), text)
    }

    @Test
    fun `a body without a Content-Type is exported as Base64`() {
        assertEquals("base64", bodyForCsv("Host: a", byteArrayOf(1, 2, 3)).first)
    }

    @Test
    fun `an empty body is empty text`() {
        assertEquals("text" to "", bodyForCsv("Content-Type: image/png", ByteArray(0)))
    }

    @Test
    fun `Base64 pads like the standard encoder`() {
        for (length in 0..5) {
            val bytes = ByteArray(length) { (it * 37).toByte() }
            assertEquals(java.util.Base64.getEncoder().encodeToString(bytes), base64(bytes))
        }
    }

    @Test
    fun `fields with commas, quotes or line breaks are quoted`() {
        assertEquals("plain", csvEscape("plain"))
        assertEquals("\"a,b\"", csvEscape("a,b"))
        assertEquals("\"say \"\"hi\"\"\"", csvEscape("say \"hi\""))
        assertEquals("\"Host: a\nAccept: b\"", csvEscape("Host: a\nAccept: b"))
    }

    @Test
    fun `a row has one column per header column`() {
        val request = RequestWithConnectionIsTracker(
            id = 1, connectionId = 2, timestamp = 3, headers = "Host: a\nContent-Type: text/plain",
            content = "x,y".toByteArray(), contentLength = 3, contentTruncated = false, method = "GET",
            remoteHost = "a", remotePath = "/", remoteIp = "1.2.3.4", remotePort = 80, localIp = "10.0.0.1",
            localPort = 1234, initiatorId = 1000, initiatorPkg = "com.example", connectionIsTracker = false
        )
        val row = requestCsvRow(request)
        assertEquals("1,3,\"Host: a\nContent-Type: text/plain\",\"x,y\",text,3,false,GET,a,/,1.2.3.4,80,10.0.0.1,1234,1000,com.example,false", row)
        assertEquals(REQUEST_CSV_HEADER.split(',').size, 17)
    }
}
