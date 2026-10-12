package de.tomcory.heimdall.service

import de.tomcory.heimdall.service.CaptureExportOptions.Format
import de.tomcory.heimdall.service.CaptureExportOptions.InvalidOptionException
import de.tomcory.heimdall.service.CaptureExportOptions.SessionSelector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** The extras of the adb export command, and its result strings. */
class CaptureExportOptionsTest {

    @Test
    fun `without extras the latest session is exported as messages and connections`() {
        val options = CaptureExportOptions.parse(null, null, null)
        assertEquals(SessionSelector.Latest, options.session)
        assertEquals(setOf(Format.MESSAGES, Format.CONNECTIONS), options.formats)
        assertEquals(emptyList<String>(), options.apps)
        assertEquals(options, CaptureExportOptions.parse(" Latest ", " ", ""))
    }

    @Test
    fun `session, apps and formats are taken over`() {
        val options = CaptureExportOptions.parse("12", "com.example.app, org.example.other", "SQLite,messages")
        assertEquals(SessionSelector.Id(12), options.session)
        assertEquals(listOf("com.example.app", "org.example.other"), options.apps)
        assertEquals(setOf(Format.SQLITE, Format.MESSAGES), options.formats)
        assertEquals(SessionSelector.All, CaptureExportOptions.parse("all", null, null).session)
    }

    @Test
    fun `a value that is not what its option takes is refused with its reason`() {
        fun reason(block: () -> Unit) = assertThrows(InvalidOptionException::class.java) { block() }.reason
        assertEquals("invalid_session", reason { CaptureExportOptions.parse("newest", null, null) })
        assertEquals("invalid_session", reason { CaptureExportOptions.parse("-3", null, null) })
        assertEquals("invalid_apps", reason { CaptureExportOptions.parse(null, "not a package", null) })
        assertEquals("invalid_formats", reason { CaptureExportOptions.parse(null, null, "messages,csv") })
    }

    @Test
    fun `the result names the folder, the session and the records per format`() {
        assertEquals(
            "status=exported dir=/sdcard/x/12-20261012-120000 session=12 messages=131 connections=48",
            CaptureCommandResult.exported("/sdcard/x/12-20261012-120000", 12, linkedMapOf("messages" to 131, "connections" to 48))
        )
        assertEquals("status=exported dir=/d session=all", CaptureCommandResult.exported("/d", null, emptyMap()))
        assertEquals("status=running dir=/d", CaptureCommandResult.exportRunning("/d"))
    }
}
