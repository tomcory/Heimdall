package de.tomcory.heimdall.core.export.util

import org.junit.Assert.assertEquals
import org.junit.Test

class BodyTest {

    @Test
    fun `a textual body is exported as text`() {
        val (encoding, text) = bodyAsText("Host: a\nContent-Type: application/json; charset=utf-8", """{"a":"ä"}""".toByteArray())
        assertEquals("text", encoding)
        assertEquals("""{"a":"ä"}""", text)
    }

    @Test
    fun `a declared charset is used`() {
        val (_, text) = bodyAsText("content-type: text/plain; charset=ISO-8859-1", "ä".toByteArray(Charsets.ISO_8859_1))
        assertEquals("ä", text)
    }

    @Test
    fun `a binary body is exported as Base64`() {
        val bytes = ByteArray(256) { it.toByte() }
        val (encoding, text) = bodyAsText("Content-Type: image/png", bytes)
        assertEquals("base64", encoding)
        assertEquals(java.util.Base64.getEncoder().encodeToString(bytes), text)
    }

    @Test
    fun `a body without a Content-Type is exported as Base64`() {
        assertEquals("base64", bodyAsText("Host: a", byteArrayOf(1, 2, 3)).first)
    }

    @Test
    fun `an empty body is empty text`() {
        assertEquals("text" to "", bodyAsText("Content-Type: image/png", ByteArray(0)))
    }

    @Test
    fun `Base64 pads like the standard encoder`() {
        for (length in 0..5) {
            val bytes = ByteArray(length) { (it * 37).toByte() }
            assertEquals(java.util.Base64.getEncoder().encodeToString(bytes), base64(bytes))
        }
    }

    @Test
    fun `stored headers become pairs in their order`() {
        assertEquals(
            listOf("Host" to "example.com", "X-Time" to "12:30:00", "Empty" to "", "NoColon" to ""),
            headerPairs("Host: example.com\nX-Time: 12:30:00\n\nEmpty:\nNoColon")
        )
        assertEquals(emptyList<Pair<String, String>>(), headerPairs(""))
    }
}
