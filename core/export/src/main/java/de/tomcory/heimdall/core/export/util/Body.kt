package de.tomcory.heimdall.core.export.util

import java.nio.charset.Charset

/**
 * A stored body as text for an export: decoded as text if the message's Content-Type says it is
 * text, Base64 otherwise, so that binary bodies are exported unchanged.
 *
 * @param headers The stored headers, one "Name: value" per line.
 * @return the encoding ("text" or "base64") and the body in it.
 */
fun bodyAsText(headers: String, content: ByteArray): Pair<String, String> {
    val contentType = headers.lineSequence()
        .firstOrNull { it.startsWith("content-type:", ignoreCase = true) }
        ?.substringAfter(':')?.trim()?.lowercase()
    if (content.isEmpty() || (contentType != null && isTextual(contentType))) {
        return "text" to String(content, charsetOf(contentType))
    }
    return "base64" to base64(content)
}

private fun isTextual(contentType: String): Boolean {
    val mime = contentType.substringBefore(';').trim()
    return mime.startsWith("text/") ||
        mime.endsWith("+json") || mime.endsWith("+xml") ||
        mime in setOf(
            "application/json", "application/xml", "application/javascript",
            "application/x-javascript", "application/ecmascript", "application/x-www-form-urlencoded"
        )
}

private fun charsetOf(contentType: String?): Charset {
    val name = contentType?.split(';')
        ?.map { it.trim() }
        ?.firstOrNull { it.startsWith("charset=") }
        ?.substringAfter('=')?.trim('"')
    return try {
        if (name != null) Charset.forName(name) else Charsets.UTF_8
    } catch (e: Exception) {
        Charsets.UTF_8
    }
}

private const val BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

/** Standard Base64 with padding. java.util.Base64 needs API 26, the app's minimum is 24. */
fun base64(bytes: ByteArray): String {
    val out = StringBuilder((bytes.size + 2) / 3 * 4)
    var i = 0
    while (i < bytes.size) {
        val b0 = bytes[i].toInt() and 0xFF
        val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
        val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
        out.append(BASE64_ALPHABET[b0 shr 2])
        out.append(BASE64_ALPHABET[((b0 and 0x03) shl 4) or (b1 shr 4)])
        out.append(if (i + 1 < bytes.size) BASE64_ALPHABET[((b1 and 0x0F) shl 2) or (b2 shr 6)] else '=')
        out.append(if (i + 2 < bytes.size) BASE64_ALPHABET[b2 and 0x3F] else '=')
        i += 3
    }
    return out.toString()
}

/** The stored headers, one "Name: value" per line, as name and value pairs in their order. */
fun headerPairs(headers: String): List<Pair<String, String>> =
    headers.lineSequence()
        .filter { it.isNotBlank() }
        .map { line ->
            val separator = line.indexOf(':')
            if (separator < 0) line.trim() to "" else line.substring(0, separator).trim() to line.substring(separator + 1).trim()
        }
        .toList()
