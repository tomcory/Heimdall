package de.tomcory.heimdall.service

import de.tomcory.heimdall.service.VpnServiceLifecycle.LaunchOutcome
import de.tomcory.heimdall.service.VpnServiceLifecycle.State
import de.tomcory.heimdall.service.VpnServiceLifecycle.StopAction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnServiceLifecycleTest {

    @Test
    fun `a start followed by a stop runs the VPN and shuts it down`() {
        val lifecycle = VpnServiceLifecycle()

        assertTrue(lifecycle.requestStart())
        assertEquals(State.STARTING, lifecycle.state)
        assertEquals(LaunchOutcome.RUNNING, lifecycle.launchFinished(success = true))
        assertEquals(State.RUNNING, lifecycle.state)

        assertEquals(StopAction.SHUT_DOWN, lifecycle.requestStop())
        assertEquals(State.STOPPING, lifecycle.state)
        lifecycle.stopped()
        assertEquals(State.IDLE, lifecycle.state)
    }

    @Test
    fun `a second start while the VPN is starting or running is a no-op`() {
        val lifecycle = VpnServiceLifecycle()
        assertTrue(lifecycle.requestStart())

        assertFalse(lifecycle.requestStart())
        assertEquals(State.STARTING, lifecycle.state)

        lifecycle.launchFinished(success = true)
        assertFalse(lifecycle.requestStart())
        assertEquals(State.RUNNING, lifecycle.state)
    }

    @Test
    fun `a stop during startup shuts the VPN down once it is up`() {
        val lifecycle = VpnServiceLifecycle()
        lifecycle.requestStart()

        assertEquals(StopAction.DEFERRED, lifecycle.requestStop())
        assertEquals(State.STARTING, lifecycle.state)

        assertEquals(LaunchOutcome.SHUT_DOWN, lifecycle.launchFinished(success = true))
        assertEquals(State.STOPPING, lifecycle.state)
    }

    @Test
    fun `a failed start is aborted and leaves the service ready for the next start`() {
        val lifecycle = VpnServiceLifecycle()
        lifecycle.requestStart()

        assertEquals(LaunchOutcome.ABORT, lifecycle.launchFinished(success = false))
        assertEquals(State.STOPPING, lifecycle.state)
        lifecycle.stopped()

        assertTrue(lifecycle.requestStart())
    }

    @Test
    fun `a stop deferred during a start does not carry over to the next start`() {
        val lifecycle = VpnServiceLifecycle()
        lifecycle.requestStart()
        lifecycle.requestStop()
        lifecycle.launchFinished(success = false)
        lifecycle.stopped()

        lifecycle.requestStart()
        assertEquals(LaunchOutcome.RUNNING, lifecycle.launchFinished(success = true))
    }

    @Test
    fun `a stop without a running VPN only stops the service`() {
        assertEquals(StopAction.STOP_IDLE_SERVICE, VpnServiceLifecycle().requestStop())
    }

    @Test
    fun `starts and stops during a shutdown are dropped`() {
        val lifecycle = VpnServiceLifecycle()
        lifecycle.requestStart()
        lifecycle.launchFinished(success = true)
        lifecycle.requestStop()

        assertFalse(lifecycle.requestStart())
        assertEquals(StopAction.IGNORE, lifecycle.requestStop())
        assertEquals(State.STOPPING, lifecycle.state)
    }

    @Test(expected = IllegalStateException::class)
    fun `reporting a finished start without one under way is an error`() {
        VpnServiceLifecycle().launchFinished(success = true)
    }
}
