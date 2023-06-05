package de.tomcory.heimdall.persistence.export.util

fun swapJsonQuotes(json: String): String {
    val sb = StringBuilder()
    var insideString = false
    var insideEscape = false

    for (ch in json) {
        if (insideEscape) {
            if(ch.isLetterOrDigit()) {
                sb.append('\\')
            }
            sb.append(ch)
            insideEscape = false
            continue
        }

        when (ch) {
            '\\' -> {
                sb.append(ch)
                insideEscape = true
            }
            '\'' -> {
                sb.append('"')
                insideString = !insideString
            }
            '"' -> {
                sb.append('\'')
                insideString = !insideString
            }
            else -> sb.append(ch)
        }
    }

    return sb.toString()
}