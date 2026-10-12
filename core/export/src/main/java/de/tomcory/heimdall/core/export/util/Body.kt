package de.tomcory.heimdall.core.export.util

import java.util.Base64

/** The encoding every exported body has, as records name it. */
const val BODY_ENCODING = "base64"

/**
 * Standard Base64 with padding, which is how every body is exported: the bytes as they were sent,
 * whatever they are (text in any charset, compressed, binary), and nothing in them that a line or
 * a string of the export would have to escape.
 */
fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

/** The stored headers, one "Name: value" per line, as name and value pairs in their order. */
fun headerPairs(headers: String): List<Pair<String, String>> =
    headers.lineSequence()
        .filter { it.isNotBlank() }
        .map { line ->
            val separator = line.indexOf(':')
            if (separator < 0) line.trim() to "" else line.substring(0, separator).trim() to line.substring(separator + 1).trim()
        }
        .toList()
