package de.tomcory.heimdall.core.export.jsonl

import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.Permission
import de.tomcory.heimdall.core.database.entity.Tracker
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The records of an export's `scans.jsonl`: what the scanners found in one installed app, one JSON object
 * per line, in the form of Ratatoskr's `app_scan` schema.
 */
object ScanRecords {

    /** Name written into `catalogue.source`. */
    const val CATALOGUE = "exodus"

    /**
     * @param libraries The trackers found in the app, or null if the app could not be checked for them
     *   (an empty catalogue, an APK that could not be read).
     * @param catalogueSize How many trackers the catalogue held.
     * @param sessionId The capture session the export was made for, or null for all sessions.
     */
    fun app(
        app: App,
        permissions: List<Permission>,
        libraries: List<Tracker>?,
        catalogueSize: Int,
        scannedAt: Long,
        sessionId: Long?,
        tag: String?,
        version: String
    ): JsonObject = buildJsonObject {
        put("id", "${sessionId ?: "all"}-${app.packageName}")
        put("scanned_at", scannedAt)
        put("app", buildJsonObject {
            put("package", app.packageName)
            put("label", app.label)
            put("version_name", app.versionName)
            put("version_code", app.versionCode)
            put("is_system", app.isSystem)
        })
        put("permissions", buildJsonArray {
            permissions.sortedBy { it.permissionName }.forEach { permission ->
                add(buildJsonObject {
                    put("name", permission.permissionName)
                    put("dangerous", permission.dangerous)
                })
            }
        })
        if (libraries == null) {
            put("libraries", JsonNull)
        } else {
            put("libraries", buildJsonArray {
                libraries.sortedBy { it.name }.forEach { tracker ->
                    add(buildJsonObject {
                        put("exodus_id", tracker.id)
                        put("name", tracker.name)
                        put("code_signature", tracker.codeSignature)
                        put("network_signature", tracker.networkSignature)
                        put("web", tracker.web)
                    })
                }
            })
        }
        put("catalogue", buildJsonObject {
            put("source", CATALOGUE)
            put("trackers", catalogueSize)
        })
        put("capture", buildJsonObject {
            put("backend", CaptureRecords.BACKEND)
            put("version", version)
            put("session", sessionId)
            put("tag", tag)
        })
    }
}
