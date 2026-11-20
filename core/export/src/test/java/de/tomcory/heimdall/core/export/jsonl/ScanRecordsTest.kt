package de.tomcory.heimdall.core.export.jsonl

import de.tomcory.heimdall.core.database.entity.App
import de.tomcory.heimdall.core.database.entity.Permission
import de.tomcory.heimdall.core.database.entity.Tracker
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanRecordsTest {

    private val app = App(packageName = "com.example.app", label = "Example", versionName = "1.6.4", versionCode = 64)
    private val permissions = listOf(
        Permission("android.permission.INTERNET", dangerous = false),
        Permission("android.permission.ACCESS_FINE_LOCATION", dangerous = true)
    )
    private val firebase = Tracker(
        id = 27, name = "Google Firebase Analytics", codeSignature = "com.google.firebase.analytics",
        networkSignature = "firebase.com", creationDate = "2017-09-24", web = "https://firebase.google.com/"
    )

    private fun JsonObject.obj(key: String) = getValue(key).jsonObject
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content

    @Test
    fun `a scan names the app, its permissions and its libraries`() {
        val record = ScanRecords.app(app, permissions, listOf(firebase), 432, 1792000000000, 12, "run-1", "0.1")

        assertEquals("12-com.example.app", record.text("id"))
        assertEquals(1792000000000, record.getValue("scanned_at").jsonPrimitive.long)
        assertEquals("com.example.app", record.obj("app").text("package"))
        assertEquals(64L, record.obj("app").getValue("version_code").jsonPrimitive.long)
        assertFalse(record.obj("app").getValue("is_system").jsonPrimitive.boolean)

        val names = record.getValue("permissions").jsonArray.map { it.jsonObject.text("name") }
        assertEquals(listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"), names)
        assertTrue(record.getValue("permissions").jsonArray[0].jsonObject.getValue("dangerous").jsonPrimitive.boolean)

        val library = record.getValue("libraries").jsonArray.single().jsonObject
        assertEquals(27, library.getValue("exodus_id").jsonPrimitive.int)
        assertEquals("com.google.firebase.analytics", library.text("code_signature"))
        assertEquals(432, record.obj("catalogue").getValue("trackers").jsonPrimitive.int)
        assertEquals("heimdall", record.obj("capture").text("backend"))
        assertEquals("run-1", record.obj("capture").text("tag"))
    }

    @Test
    fun `an app that could not be checked for libraries has none, not an empty list`() {
        val record = ScanRecords.app(app, permissions, null, 0, 1, null, null, "0.1")
        assertEquals(JsonNull, record.getValue("libraries"))
        assertEquals("all-com.example.app", record.text("id"))
        assertEquals(JsonNull, record.obj("capture").getValue("session"))
    }
}
