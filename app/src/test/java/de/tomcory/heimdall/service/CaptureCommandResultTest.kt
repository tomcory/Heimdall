package de.tomcory.heimdall.service

import de.tomcory.heimdall.service.CaptureState.Phase
import de.tomcory.heimdall.service.CaptureState.Snapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/** The result strings of the adb capture commands, and the state they are built from. */
class CaptureCommandResultTest {

    private val options = CaptureSessionOptions(tag = "baseline-1", apps = listOf("com.example.app"), blockHosts = listOf("a.example", "b.example"))

    @Test
    fun `a capture is reported through its phases`() {
        val state = CaptureState()
        assertEquals("status=idle", CaptureCommandResult.status(state.snapshot.value))

        state.starting(12, options, since = 1000)
        assertEquals("status=starting session=12 tag=baseline-1", CaptureCommandResult.status(state.snapshot.value))

        state.running(12, mitm = true)
        assertEquals(
            "status=started session=12 mitm=true apps=1 blocked_hosts=2 tag=baseline-1",
            CaptureCommandResult.started(state.snapshot.value)
        )
        assertEquals(
            "status=running session=12 mitm=true apps=1 blocked_hosts=2 since=1000 tag=baseline-1",
            CaptureCommandResult.status(state.snapshot.value)
        )

        state.stopping()
        assertEquals("status=stopping session=12 tag=baseline-1", CaptureCommandResult.inTransition(state.snapshot.value))

        state.idle()
        assertEquals("status=idle last_session=12", CaptureCommandResult.status(state.snapshot.value))
        assertEquals(
            "status=stopped session=12 connections=48 requests=131 tag=baseline-1",
            CaptureCommandResult.stopped(state.snapshot.value, connections = 48, requests = 131)
        )
    }

    @Test
    fun `a failed start keeps its session and reason, the next start clears them`() {
        val state = CaptureState()
        state.starting(7, CaptureSessionOptions.NONE, since = 1)
        state.idle(failure = "vpn_consent_missing")
        assertEquals(Snapshot(phase = Phase.IDLE, sessionId = 7, since = 1, failure = "vpn_consent_missing"), state.snapshot.value)

        state.starting(8, CaptureSessionOptions.NONE, since = 2)
        assertNull(state.snapshot.value.failure)
        assertEquals(8, state.snapshot.value.sessionId)
    }

    @Test
    fun `no result contains a space inside a value`() {
        val results = listOf(
            CaptureCommandResult.error("app_not_installed", "apps=com.example.app,org.example.other"),
            CaptureCommandResult.error("vpn_consent_missing"),
            CaptureCommandResult.started(Snapshot(Phase.RUNNING, 3, "t", true, 2, 1, 5))
        )
        assertEquals("status=error reason=vpn_consent_missing", results[1])
        results.forEach { result -> result.split(' ').forEach { pair -> assertFalse(pair, pair.count { it == '=' } != 1) } }
    }
}
