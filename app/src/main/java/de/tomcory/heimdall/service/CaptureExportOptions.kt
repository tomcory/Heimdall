package de.tomcory.heimdall.service

/**
 * What a capture export covers. Kept free of Android dependencies so it can be unit tested.
 *
 * @param session Which session's traffic is exported.
 * @param apps If not empty, only the traffic of these packages. Does not apply to the database copy.
 * @param formats What is written.
 */
data class CaptureExportOptions(
    val session: SessionSelector = SessionSelector.Latest,
    val apps: List<String> = emptyList(),
    val formats: Set<Format> = DEFAULT_FORMATS
) {

    sealed interface SessionSelector {
        /** The session that was started last. */
        data object Latest : SessionSelector

        data object All : SessionSelector

        data class Id(val id: Long) : SessionSelector
    }

    /** @param fileName The file the format is written to, inside the export's folder. */
    enum class Format(val key: String, val fileName: String) {
        /** One record per HTTP request with its response. */
        MESSAGES("messages", "messages.jsonl"),

        /** One record per connection, decrypted or not. */
        CONNECTIONS("connections", "connections.jsonl"),

        /** A copy of the whole database, whatever [session] and [apps] say. */
        SQLITE("sqlite", "heimdall.sqlite")
    }

    /** A value of an adb extra that cannot be used; [reason] goes into the command's result. */
    class InvalidOptionException(val reason: String) : IllegalArgumentException(reason)

    companion object {
        val DEFAULT_FORMATS: Set<Format> = setOf(Format.MESSAGES, Format.CONNECTIONS)

        private val PACKAGE_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

        /**
         * @param session "latest" (the default), "all" or a session id.
         * @param apps Package names separated by commas.
         * @param formats Format keys separated by commas; messages and connections by default.
         * @throws InvalidOptionException for a value that is not what its option takes.
         */
        fun parse(session: String?, apps: String?, formats: String?): CaptureExportOptions {
            val selector = when (val value = session?.trim()?.lowercase().orEmpty()) {
                "", "latest" -> SessionSelector.Latest
                "all" -> SessionSelector.All
                else -> SessionSelector.Id(value.toLongOrNull()?.takeIf { it >= 0 } ?: throw InvalidOptionException("invalid_session"))
            }
            val packages = split(apps)
            if (packages.any { !PACKAGE_PATTERN.matches(it) }) {
                throw InvalidOptionException("invalid_apps")
            }
            val keys = split(formats).map { it.lowercase() }
            val chosen = keys.map { key -> Format.entries.firstOrNull { it.key == key } ?: throw InvalidOptionException("invalid_formats") }.toSet()
            return CaptureExportOptions(selector, packages, chosen.ifEmpty { DEFAULT_FORMATS })
        }

        private fun split(list: String?): List<String> =
            list?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.distinct() ?: emptyList()
    }
}
