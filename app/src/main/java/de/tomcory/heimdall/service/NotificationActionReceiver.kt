package de.tomcory.heimdall.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import timber.log.Timber

class NotificationActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent != null) {
            val action = intent.action
            if (STOP_VPN == action) {
                Timber.d("Handling intent: %s", action)
                stopVpn(context)
            } else {
                Timber.d("Unknown intent action: %s", action)
            }
        } else {
            Timber.d("Got null intent")
        }
    }

    private fun stopVpn(context: Context) {
        val serviceIntent = Intent(context, HeimdallVpnService::class.java)
        serviceIntent.putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE)
        context.startService(serviceIntent)
    }

    companion object {
        const val STOP_VPN = "de.tomcory.heimdall.ui.notification.action.STOP_VPN"
    }
}