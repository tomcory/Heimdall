package de.tomcory.heimdall.service

import android.content.Context
import android.content.pm.PackageManager
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Session
import de.tomcory.heimdall.core.export.jsonl.CaptureExclusions
import de.tomcory.heimdall.core.export.jsonl.CaptureExport
import de.tomcory.heimdall.core.export.jsonl.CaptureRecords
import de.tomcory.heimdall.core.export.jsonl.ScanRecords
import de.tomcory.heimdall.core.scanner.LibraryScanner
import de.tomcory.heimdall.core.scanner.PermissionScanner
import de.tomcory.heimdall.service.CaptureExportOptions.Format
import de.tomcory.heimdall.service.CaptureExportOptions.SessionSelector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import timber.log.Timber
import java.io.File
import java.io.Writer
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Writes captured traffic to files that can be pulled over adb or shared from the UI: messages
 * and connections as JSON Lines, a copy of the database, and the scans of the exported apps.
 *
 * An export gets a folder of its own below the app's external files directory. [MANIFEST_FILE] is
 * written last, so a folder with a manifest is a complete export. The manifest gives each file's size,
 * record count and SHA-256, the session's settings (for an export of one session whose settings were
 * recorded) and the classes of traffic the capture could not observe as messages ([CaptureExclusions]).
 */
@Singleton
class CaptureExporter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val database: HeimdallDatabase,
    private val captureState: CaptureState,
    private val permissionScanner: PermissionScanner,
    private val libraryScanner: LibraryScanner,
    private val sessionSettings: SessionSettingsStore
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
        val session = sessionId?.let { database.sessionDao().getById(it) }

        for (format in Format.entries.filter { it in options.formats }) {
            val file = File(directory, format.fileName)
            when (format) {
                Format.MESSAGES -> counts[format] = file.bufferedWriter().use { export.writeMessages(it) }
                Format.CONNECTIONS -> counts[format] = file.bufferedWriter().use { export.writeConnections(it) }
                Format.SQLITE -> copyDatabase(file)
                Format.SCANS -> counts[format] = file.bufferedWriter().use { writeScans(it, options.apps, sessionId, session, version) }
            }
            files.add(file)
        }

        val running = captureState.snapshot.value.let { it.phase != CaptureState.Phase.IDLE && (sessionId == null || it.sessionId == sessionId) }
        val settings = sessionId?.let { sessionSettings.read(it) }
        val mitm = settings?.get("mitm")?.jsonPrimitive?.booleanOrNull
        val facts = database.connectionDao().getFactsForExport(sessionId ?: CaptureExport.ALL_SESSIONS, options.apps.isNotEmpty(), options.apps)
        val exclusions = CaptureExclusions.classify(facts, mitm)
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
                        put("sha256", sha256(file))
                    })
                }
            })
            // absent where not known: an export of all sessions, or a session started before settings were recorded
            settings?.let { put("settings", it) }
            put("exclusions", buildJsonObject { exclusions.forEach { (cls, n) -> put(cls, n) } })
        }
        File(directory, MANIFEST_FILE).writeText(manifest.toString() + "\n")
        Timber.i("Capture export written to ${directory.absolutePath}: $counts")
        return Result(directory, sessionId, files + File(directory, MANIFEST_FILE), counts)
    }

    /**
     * Scans the apps and writes one record per app: [apps], or if none are given the apps with traffic in
     * the export. An app's earlier results are removed first, so that a record holds what the app requests
     * and contains as it is installed now; an app that is not installed gets no record.
     *
     * @return the number of records written.
     */
    private suspend fun writeScans(out: Writer, apps: List<String>, sessionId: Long?, session: Session?, version: String): Int {
        val pm = context.packageManager
        var written = 0
        val scanned = apps.ifEmpty { database.connectionDao().getAppsForExport(sessionId ?: CaptureExport.ALL_SESSIONS) }
        for (packageName in scanned) {
            val info = try {
                pm.getPackageInfo(packageName, PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS)
            } catch (e: PackageManager.NameNotFoundException) {
                continue
            }
            val app = appRow(pm, info)
            database.appDao().insertApps(app)
            database.appXPermissionDao().deleteForApp(packageName)
            database.appXTrackerDao().deleteForApp(packageName)
            permissionScanner.scanApp(info)
            val librariesScanned = libraryScanner.scanApp(info).success
            val record = ScanRecords.app(
                app = app,
                permissions = database.appXPermissionDao().getAppWithPermissions(packageName).permissions,
                libraries = if (librariesScanned) database.appXTrackerDao().getAppWithTrackers(packageName).trackers else null,
                catalogueSize = database.trackerDao().count(),
                scannedAt = System.currentTimeMillis(),
                sessionId = sessionId,
                tag = session?.tag,
                version = version
            )
            out.write(record.toString())
            out.write("\n")
            written++
        }
        return written
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DIGEST_BUFFER)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
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
        private const val DIGEST_BUFFER = 64 * 1024
    }
}
