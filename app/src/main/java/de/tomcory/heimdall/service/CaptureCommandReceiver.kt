package de.tomcory.heimdall.service

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import androidx.core.content.ContextCompat
import dagger.hilt.android.AndroidEntryPoint
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Session
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber
import javax.inject.Inject

/**
 * Starts and stops the traffic capture on request from adb, without going through the UI:
 *
 * ```
 * adb shell am broadcast -f 0x20 -n de.tomcory.heimdall/.service.CaptureCommandReceiver \
 *   -a de.tomcory.heimdall.action.START_CAPTURE \
 *   [--es tag <label>] [--es apps <pkg,pkg>] [--es block_hosts <host,host>] \
 *   [--ez mitm true|false] [--es quic_policy block|passthrough]
 * adb shell am broadcast -f 0x20 -n de.tomcory.heimdall/.service.CaptureCommandReceiver \
 *   -a de.tomcory.heimdall.action.STOP_CAPTURE
 * adb shell am broadcast -f 0x20 -n de.tomcory.heimdall/.service.CaptureCommandReceiver \
 *   -a de.tomcory.heimdall.action.CAPTURE_STATUS
 * ```
 *
 * The extras apply to the started session only and change no preference. The outcome is returned
 * as the broadcast's result data, which `am broadcast` prints (see [CaptureCommandResult]). A
 * start or stop that takes longer than [WAIT_MS] is reported as `starting` or `stopping`.
 *
 * The receiver is protected by `android.permission.DUMP` in the manifest, which only the shell
 * and system hold, so other apps can't trigger it. The VPN has to have been consented to once,
 * in the UI or with `appops set de.tomcory.heimdall ACTIVATE_VPN allow`.
 */
@AndroidEntryPoint
class CaptureCommandReceiver : BroadcastReceiver() {

    @Inject lateinit var database: HeimdallDatabase
    @Inject lateinit var captureState: CaptureState

    override fun onReceive(context: Context, intent: Intent) {
        val command: suspend () -> Pair<Int, String> = when (intent.action) {
            ACTION_START_CAPTURE -> { -> start(context.applicationContext, intent) }
            ACTION_STOP_CAPTURE -> { -> stop(context.applicationContext) }
            ACTION_CAPTURE_STATUS -> { -> Activity.RESULT_OK to CaptureCommandResult.status(captureState.snapshot.value) }
            else -> {
                Timber.d("Unknown intent action: ${intent.action}")
                return
            }
        }

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val (code, data) = try {
                    command()
                } catch (e: Exception) {
                    Timber.e(e, "Error handling capture command ${intent.action}")
                    Activity.RESULT_CANCELED to CaptureCommandResult.error("exception", "message=${e.javaClass.simpleName}")
                }
                Timber.i("Capture command ${intent.action}: $data")
                pendingResult.resultCode = code
                pendingResult.resultData = data
            } finally {
                pendingResult.finish()
            }
        }
    }

    private suspend fun start(context: Context, intent: Intent): Pair<Int, String> {
        val current = captureState.snapshot.value
        if (current.phase != CaptureState.Phase.IDLE) {
            // a running capture is left alone: its session and options stay what they are
            return Activity.RESULT_CANCELED to CaptureCommandResult.status(current)
        }

        val options = try {
            CaptureSessionOptions.parse(
                tag = intent.getStringExtra(EXTRA_TAG),
                apps = intent.getStringExtra(EXTRA_APPS),
                blockHosts = intent.getStringExtra(EXTRA_BLOCK_HOSTS),
                mitm = if (intent.hasExtra(EXTRA_MITM)) intent.getBooleanExtra(EXTRA_MITM, false) else null,
                quicPolicy = intent.getStringExtra(EXTRA_QUIC_POLICY)
            )
        } catch (e: CaptureSessionOptions.InvalidOptionException) {
            return Activity.RESULT_CANCELED to CaptureCommandResult.error(e.reason)
        }

        // A VPN whose allowed apps are all missing would route every app instead of none
        val missing = options.apps.filterNot { isInstalled(context, it) }
        if (missing.isNotEmpty()) {
            return Activity.RESULT_CANCELED to CaptureCommandResult.error("app_not_installed", "apps=${missing.joinToString(",")}")
        }

        if (VpnService.prepare(context) != null) {
            return Activity.RESULT_CANCELED to CaptureCommandResult.error("vpn_consent_missing")
        }

        val sessionId = database.sessionDao().insert(Session(startTime = System.currentTimeMillis(), tag = options.tag)).first()

        val serviceIntent = Intent(context, HeimdallVpnService::class.java)
            .putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.START_SERVICE)
            .putExtra(HeimdallVpnService.SESSION_ID_EXTRA, sessionId)
            .putExtra(HeimdallVpnService.SESSION_TAG_EXTRA, options.tag)
            .putExtra(HeimdallVpnService.SESSION_APPS_EXTRA, options.apps.toTypedArray())
            .putExtra(HeimdallVpnService.SESSION_BLOCK_HOSTS_EXTRA, options.blockHosts.toTypedArray())
            .putExtra(HeimdallVpnService.QUIC_POLICY_EXTRA, options.quicPolicy)
        options.mitm?.let { serviceIntent.putExtra(HeimdallVpnService.SESSION_MITM_EXTRA, it) }

        try {
            ContextCompat.startForegroundService(context, serviceIntent)
        } catch (e: Exception) {
            // On Android 12 and later the system may refuse to start a foreground service for an
            // app that is in the background (ForegroundServiceStartNotAllowedException)
            Timber.e(e, "The VPN service could not be started from the background")
            database.sessionDao().delete(sessionId)
            val reason = if (e is IllegalStateException) "background_start_not_allowed" else "start_failed"
            return Activity.RESULT_CANCELED to CaptureCommandResult.error(reason, "message=${e.javaClass.simpleName}")
        }

        // The service reports through CaptureState. Its first report replaces the snapshot of the
        // previous capture, so only snapshots of this session count.
        val outcome = withTimeoutOrNull(WAIT_MS) {
            captureState.snapshot.first {
                it.sessionId == sessionId && (it.phase == CaptureState.Phase.RUNNING || it.phase == CaptureState.Phase.IDLE)
            }
        }
        return when {
            outcome == null -> Activity.RESULT_OK to CaptureCommandResult.inTransition(
                captureState.snapshot.value.takeIf { it.sessionId == sessionId }
                    ?: CaptureState.Snapshot(CaptureState.Phase.STARTING, sessionId, options.tag)
            )
            outcome.phase == CaptureState.Phase.RUNNING -> Activity.RESULT_OK to CaptureCommandResult.started(outcome)
            else -> {
                database.sessionDao().delete(sessionId)
                Activity.RESULT_CANCELED to CaptureCommandResult.error(outcome.failure ?: "start_failed")
            }
        }
    }

    private suspend fun stop(context: Context): Pair<Int, String> {
        val current = captureState.snapshot.value
        if (current.phase == CaptureState.Phase.IDLE) {
            // nothing to stop, and starting the service only to stop it again is not allowed
            // from the background
            return Activity.RESULT_OK to CaptureCommandResult.status(current)
        }

        context.startService(
            Intent(context, HeimdallVpnService::class.java)
                .putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE)
        )

        val stopped = withTimeoutOrNull(WAIT_MS) {
            captureState.snapshot.first { it.phase == CaptureState.Phase.IDLE }
        } ?: return Activity.RESULT_OK to CaptureCommandResult.inTransition(captureState.snapshot.value)

        val connections = database.connectionDao().countForSession(stopped.sessionId)
        val requests = database.requestDao().countForSession(stopped.sessionId)
        return Activity.RESULT_OK to CaptureCommandResult.stopped(stopped, connections, requests)
    }

    private fun isInstalled(context: Context, packageName: String): Boolean = try {
        context.packageManager.getApplicationInfo(packageName, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    companion object {
        const val ACTION_START_CAPTURE = "de.tomcory.heimdall.action.START_CAPTURE"
        const val ACTION_STOP_CAPTURE = "de.tomcory.heimdall.action.STOP_CAPTURE"
        const val ACTION_CAPTURE_STATUS = "de.tomcory.heimdall.action.CAPTURE_STATUS"

        const val EXTRA_TAG = "tag"
        const val EXTRA_APPS = "apps"
        const val EXTRA_BLOCK_HOSTS = "block_hosts"
        const val EXTRA_MITM = "mitm"
        const val EXTRA_QUIC_POLICY = "quic_policy"

        /** How long a command waits for the capture to come up or go down before it answers. */
        private const val WAIT_MS = 8_000L
    }
}
