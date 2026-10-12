package de.tomcory.heimdall.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * What the traffic capture is doing right now, as [HeimdallVpnService] reports it. Lives in the
 * app's process only: unlike the `vpnActive` preference it cannot be left over from a process that
 * died, which is what [CaptureCommandReceiver] needs to answer truthfully.
 */
@Singleton
class CaptureState @Inject constructor() {

    enum class Phase { IDLE, STARTING, RUNNING, STOPPING }

    /**
     * @param sessionId The session of the capture that is starting, running or stopping, and after
     * it has stopped the session that ran last; -1 if there is none.
     * @param since When the capture was asked to start (epoch milliseconds).
     * @param failure Why the last start did not bring the capture up, or null.
     */
    data class Snapshot(
        val phase: Phase = Phase.IDLE,
        val sessionId: Long = -1,
        val tag: String? = null,
        val mitm: Boolean = false,
        val apps: Int = 0,
        val blockedHosts: Int = 0,
        val since: Long = 0,
        val failure: String? = null
    )

    private val _snapshot = MutableStateFlow(Snapshot())
    val snapshot: StateFlow<Snapshot> = _snapshot

    fun starting(sessionId: Long, options: CaptureSessionOptions, since: Long) {
        _snapshot.value = Snapshot(
            phase = Phase.STARTING,
            sessionId = sessionId,
            tag = options.tag,
            apps = options.apps.size,
            blockedHosts = options.blockHosts.size,
            since = since
        )
    }

    fun running(sessionId: Long, mitm: Boolean) {
        _snapshot.value = _snapshot.value.copy(phase = Phase.RUNNING, sessionId = sessionId, mitm = mitm)
    }

    fun stopping() {
        _snapshot.value = _snapshot.value.copy(phase = Phase.STOPPING)
    }

    /** @param failure Set if this ends a start that did not bring the capture up. */
    fun idle(failure: String? = null) {
        _snapshot.value = _snapshot.value.copy(phase = Phase.IDLE, failure = failure)
    }
}
