package de.tomcory.heimdall.service

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.export.jsonl.CaptureExport
import de.tomcory.heimdall.core.export.jsonl.CaptureRecords
import de.tomcory.heimdall.service.CaptureExportOptions.Format
import de.tomcory.heimdall.service.CaptureExportOptions.SessionSelector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import timber.log.Timber
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Writes captured traffic to files that can be pulled over adb or shared from the UI: messages
 * and connections as JSON Lines, and a copy of the database.
 *
 * An export gets a folder of its own below the app's external files directory. [MANIFEST_FILE] is
 * written last, so a folder with a manifest is a complete export.
 */
@Singleton
class CaptureExporter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val database: HeimdallDatabase,
    private val captureState: CaptureState
) {
    // exports outlive whoever asked for them: a broadcast receiver has to answer within seconds
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * @param sessionId The exported session, or null for all sessions.
     * @param counts Records written per JSON Lines format.
     */
    data class Result(val directory: File, val sessionId: Long?, val files: List<File>, val counts: Map<Format, Int>)

    /** An export that has been given its folder and is under way. */
    class Running(val directory: File, val result: Deferred<Result>)

    /** The selected session does not exist; [reason] goes into the adb command's result. */
    class NoSuchSessionException(val reason: String) : Exception(reason)

    /**
     * Starts an export.
     *
     * @throws NoSuchSessionException if [options] selects a session that does not exist.
     */
    suspend fun start(options: CaptureExportOptions): Running {
        val sessionId: Long? = when (val selector = options.session) {
            SessionSelector.All -> null
            SessionSelector.Latest -> database.sessionDao().getLatestSession()?.id ?: throw NoSuchSessionException("no_session")
            is SessionSelector.Id -> database.sessionDao().getById(selector.id)?.id ?: throw NoSuchSessionException("unknown_session")
        }
        val directory = newDirectory("${sessionId ?: "all"}-${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())}")
        return Running(directory, scope.async { export(options, sessionId, directory) })
    }

    private suspend fun export(options: CaptureExportOptions, sessionId: Long?, directory: File): Result {
        val version = versionName()
        val export = CaptureExport(
            database.sessionDao(), database.connectionDao(), database.requestDao(), database.responseDao(),
            sessionId, options.apps, version
        )
        val counts = LinkedHashMap<Format, Int>()
        val files = mutableListOf<File>()

        for (format in Format.entries.filter { it in options.formats }) {
            val file = File(directory, format.fileName)
            when (format) {
                Format.MESSAGES -> counts[format] = file.bufferedWriter().use { export.writeMessages(it) }
                Format.CONNECTIONS -> counts[format] = file.bufferedWriter().use { export.writeConnections(it) }
                Format.SQLITE -> copyDatabase(file)
            }
            files.add(file)
        }

        val session = sessionId?.let { database.sessionDao().getById(it) }
        val running = captureState.snapshot.value.let { it.phase != CaptureState.Phase.IDLE && (sessionId == null || it.sessionId == sessionId) }
        val manifest = buildJsonObject {
            put("backend", CaptureRecords.BACKEND)
            put("version", version)
            put("exported_at", System.currentTimeMillis())
            put("session", sessionId)
            put("tag", session?.tag)
            put("session_start", session?.startTime)
            put("session_end", session?.endTime?.takeIf { it >= 0 })
            // an export taken while the capture runs holds what had been recorded until then
            put("capture_running", running)
            put("apps", JsonArray(options.apps.map { JsonPrimitive(it) }))
            put("files", buildJsonObject {
                files.forEach { file ->
                    put(file.name, buildJsonObject {
                        put("bytes", file.length())
                        Format.entries.firstOrNull { it.fileName == file.name }?.let { format -> counts[format]?.let { put("records", it) } }
                    })
                }
            })
        }
        File(directory, MANIFEST_FILE).writeText(manifest.toString() + "\n")
        Timber.i("Capture export written to ${directory.absolutePath}: $counts")
        return Result(directory, sessionId, files + File(directory, MANIFEST_FILE), counts)
    }

    /** Copies the database file after folding the write-ahead log into it. */
    private fun copyDatabase(target: File) {
        database.openHelper.writableDatabase.query("PRAGMA wal_checkpoint(FULL)").use { it.moveToFirst() }
        val source = context.getDatabasePath(database.openHelper.databaseName ?: "heimdall")
        source.copyTo(target, overwrite = true)
    }

    /** A new folder of that name, or of that name with a number if exports follow within a second. */
    @Synchronized
    private fun newDirectory(name: String): File {
        val root = exportRoot()
        var directory = File(root, name)
        var suffix = 2
        while (directory.exists()) {
            directory = File(root, "$name-${suffix++}")
        }
        if (!directory.mkdirs()) {
            throw IllegalStateException("Cannot create ${directory.absolutePath}")
        }
        return directory
    }

    private fun exportRoot(): File = context.getExternalFilesDir(EXPORT_DIR_NAME) ?: File(context.filesDir, EXPORT_DIR_NAME)

    private fun versionName(): String = try {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "unknown"
    } catch (e: Exception) {
        "unknown"
    }

    companion object {
        const val MANIFEST_FILE = "manifest.json"
        private const val EXPORT_DIR_NAME = "export"
    }
}
