package de.tomcory.heimdall.service

/**
 * The result strings of [CaptureCommandReceiver], which `am broadcast` prints: `key=value` pairs
 * separated by spaces, starting with `status`. No value contains a space. Kept free of Android
 * dependencies so it can be unit tested.
 */
object CaptureCommandResult {

    fun started(snapshot: CaptureState.Snapshot) =
        "status=started session=${snapshot.sessionId} mitm=${snapshot.mitm} apps=${snapshot.apps} blocked_hosts=${snapshot.blockedHosts}" + tag(snapshot)

    /** The command returned before the capture was up or down; `CAPTURE_STATUS` tells how it went on. */
    fun inTransition(snapshot: CaptureState.Snapshot) =
        "status=${snapshot.phase.name.lowercase()} session=${snapshot.sessionId}" + tag(snapshot)

    fun stopped(snapshot: CaptureState.Snapshot, connections: Int, requests: Int) =
        "status=stopped session=${snapshot.sessionId} connections=$connections requests=$requests" + tag(snapshot)

    fun status(snapshot: CaptureState.Snapshot): String = when (snapshot.phase) {
        CaptureState.Phase.IDLE -> "status=idle" + if (snapshot.sessionId >= 0) " last_session=${snapshot.sessionId}" else ""
        CaptureState.Phase.RUNNING ->
            "status=running session=${snapshot.sessionId} mitm=${snapshot.mitm} apps=${snapshot.apps} blocked_hosts=${snapshot.blockedHosts} since=${snapshot.since}" + tag(snapshot)
        else -> inTransition(snapshot)
    }

    /**
     * @param sessionId The exported session, or null for all sessions.
     * @param counts Records written, by format.
     */
    fun exported(directory: String, sessionId: Long?, counts: Map<String, Int>) =
        "status=exported dir=$directory session=${sessionId ?: "all"}" + counts.entries.joinToString("") { " ${it.key}=${it.value}" }

    /** The command returned before the export was complete; it is once its folder holds the manifest. */
    fun exportRunning(directory: String) = "status=running dir=$directory"

    /** @param detail Further `key=value` pairs, already formatted. */
    fun error(reason: String, detail: String = "") =
        "status=error reason=$reason" + if (detail.isNotEmpty()) " $detail" else ""

    private fun tag(snapshot: CaptureState.Snapshot) = snapshot.tag?.let { " tag=$it" } ?: ""
}
