package de.tomcory.heimdall.service

/**
 * Keeps track of what [HeimdallVpnService] is doing and decides what a start or stop request
 * does in that state. Start and stop requests arrive on the main thread while the work they
 * trigger runs on background threads, so without this a second START found the interface
 * already established, failed, and tore down the running VPN, and a STOP that arrived while the
 * VPN was still starting was lost. Kept free of Android dependencies so it can be unit tested.
 */
class VpnServiceLifecycle {

    enum class State {
        /** The VPN is not running and nothing is under way. */
        IDLE,

        /** A start is under way: the interface and the components are being set up. */
        STARTING,

        /** The VPN is up. */
        RUNNING,

        /** The VPN is being shut down, or a failed start is being cleaned up. */
        STOPPING
    }

    /** What the service has to do about a stop request. */
    enum class StopAction {
        /** Shut the VPN down now. */
        SHUT_DOWN,

        /** A start is under way; [launchFinished] will ask for the shutdown when it is done. */
        DEFERRED,

        /** Nothing is running: the request itself started the service, which only has to stop again. */
        STOP_IDLE_SERVICE,

        /** A shutdown is already under way. */
        IGNORE
    }

    /** What the service has to do once the start it was told to launch has finished. */
    enum class LaunchOutcome {
        /** The VPN is up. */
        RUNNING,

        /** The VPN came up, but a stop was requested in the meantime: shut it down again. */
        SHUT_DOWN,

        /** The VPN did not come up: clean up, then report [stopped]. */
        ABORT
    }

    @get:Synchronized
    var state = State.IDLE
        private set

    private var stopPending = false

    /**
     * @return whether the caller is to launch the VPN. False if it is already starting or
     * running, where a second start is a no-op, or shutting down, where the request is dropped
     * because the service is about to stop itself.
     */
    @Synchronized
    fun requestStart(): Boolean {
        if (state != State.IDLE) {
            return false
        }
        state = State.STARTING
        return true
    }

    @Synchronized
    fun requestStop(): StopAction {
        return when (state) {
            State.RUNNING -> {
                state = State.STOPPING
                StopAction.SHUT_DOWN
            }
            State.STARTING -> {
                stopPending = true
                StopAction.DEFERRED
            }
            State.IDLE -> StopAction.STOP_IDLE_SERVICE
            State.STOPPING -> StopAction.IGNORE
        }
    }

    /**
     * Reports the end of the start that [requestStart] asked for.
     *
     * @param success Whether the interface was established and the components were launched.
     */
    @Synchronized
    fun launchFinished(success: Boolean): LaunchOutcome {
        if (state != State.STARTING) {
            throw IllegalStateException("No start is under way (state $state)")
        }
        return if (!success) {
            state = State.STOPPING
            LaunchOutcome.ABORT
        } else if (stopPending) {
            state = State.STOPPING
            LaunchOutcome.SHUT_DOWN
        } else {
            state = State.RUNNING
            LaunchOutcome.RUNNING
        }
    }

    /** Reports that the shutdown, or the cleanup after a failed start, is complete. */
    @Synchronized
    fun stopped() {
        state = State.IDLE
        stopPending = false
    }
}
