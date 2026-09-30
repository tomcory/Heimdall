package de.tomcory.heimdall.service

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dagger.hilt.android.AndroidEntryPoint
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.core.vpn.mitm.KeyStoreHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber
import java.io.File
import javax.inject.Inject

/**
 * Generates Heimdall's MitM root CA on request from adb, without going through the UI:
 *
 * ```
 * adb shell am broadcast -f 0x20 \
 *   -n de.tomcory.heimdall/.service.CaCertificateCommandReceiver \
 *   -a de.tomcory.heimdall.action.GENERATE_CA_CERT [--ez force true]
 * adb pull /sdcard/Android/data/de.tomcory.heimdall/files/ca/ .
 * ```
 *
 * The receiver is protected by `android.permission.DUMP` in the manifest, which only the shell
 * and system hold, so other apps can't trigger it. The outcome is returned as the broadcast's
 * result data, which `am broadcast` prints.
 */
@AndroidEntryPoint
class CaCertificateCommandReceiver : BroadcastReceiver() {

    @Inject lateinit var preferences: PreferencesDataSource

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_GENERATE_CA_CERT) {
            Timber.d("Unknown intent action: ${intent.action}")
            return
        }

        val force = intent.getBooleanExtra(EXTRA_FORCE, false)
        val exportDir = context.getExternalFilesDir(EXPORT_DIR_NAME)
            ?: File(context.filesDir, EXPORT_DIR_NAME)
        val generator = CaCertificateGenerator(
            keyStoreDir = File(context.filesDir, "keystore"),
            exportDir = exportDir,
            isVpnActive = { preferences.vpnActive.first() }
        )

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val (code, data) = when (val outcome = generator.generate(force)) {
                    is CaCertificateGenerator.Outcome.Generated ->
                        Activity.RESULT_OK to describe("generated", outcome.export)
                    is CaCertificateGenerator.Outcome.Reused ->
                        Activity.RESULT_OK to describe("reused", outcome.export)
                    CaCertificateGenerator.Outcome.RefusedVpnActive ->
                        Activity.RESULT_CANCELED to "status=refused reason=vpn_active"
                    is CaCertificateGenerator.Outcome.Failed -> {
                        Timber.e(outcome.error, "Error generating root CA certificate via adb")
                        Activity.RESULT_CANCELED to "status=error message=${outcome.error.message}"
                    }
                }
                Timber.i("Root CA certificate command (force=$force): $data")
                pendingResult.resultCode = code
                pendingResult.resultData = data
            } finally {
                pendingResult.finish()
            }
        }
    }

    private fun describe(status: String, export: KeyStoreHelper.CaExport) =
        "status=$status hash=${export.hash} pem=${export.pemFile.absolutePath} system=${export.systemFile.absolutePath}"

    companion object {
        const val ACTION_GENERATE_CA_CERT = "de.tomcory.heimdall.action.GENERATE_CA_CERT"
        const val EXTRA_FORCE = "force"
        private const val EXPORT_DIR_NAME = "ca"
    }
}
