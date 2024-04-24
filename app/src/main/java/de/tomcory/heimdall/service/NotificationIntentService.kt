package de.tomcory.heimdall.service

import android.app.IntentService
import android.content.Intent
import timber.log.Timber

class NotificationIntentService : IntentService(NotificationIntentService::class.java.simpleName) {
    override fun onHandleIntent(intent: Intent?) {
        if (intent != null) {
            val action = intent.action
            if (STOP_VPN == action) {
                Timber.d("Handling intent: %s", action)
                stopVpn()
            } else {
                Timber.d("Unknown intent action: %s", action)
            }
        } else {
            Timber.d("Got null intent")
        }
    }

    private fun stopVpn() {
        val serviceIntent = Intent(this, HeimdallVpnService::class.java)
        serviceIntent.putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE)
        startService(serviceIntent)
    }

    companion object {
        const val STOP_VPN = "de.tomcory.heimdall.ui.notification.action.STOP_VPN"
    }
}
