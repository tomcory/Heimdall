package de.tomcory.heimdall.service

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.core.export.jsonl.CaptureSettings
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import timber.log.Timber
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The settings each capture session was started with, one file per session below the app's files
 * directory. Kept outside the database so that recording them needs no schema change; an export
 * reads a session's file into its manifest.
 */
@Singleton
class SessionSettingsStore @Inject constructor(@ApplicationContext context: Context) {
    private val directory = File(context.filesDir, DIRECTORY)

    fun write(sessionId: Long, settings: CaptureSettings) {
        try {
            directory.mkdirs()
            file(sessionId).writeText(settings.toJson().toString() + "\n")
        } catch (e: Exception) {
            Timber.e(e, "Could not record the settings of session $sessionId")
        }
    }

    /** The settings a session was started with, or null if they were not recorded. */
    fun read(sessionId: Long): JsonObject? = try {
        file(sessionId).takeIf { it.isFile }?.let { Json.parseToJsonElement(it.readText()).jsonObject }
    } catch (e: Exception) {
        Timber.w(e, "Could not read the settings of session $sessionId")
        null
    }

    private fun file(sessionId: Long) = File(directory, "$sessionId.json")

    companion object {
        private const val DIRECTORY = "session-settings"
    }
}
