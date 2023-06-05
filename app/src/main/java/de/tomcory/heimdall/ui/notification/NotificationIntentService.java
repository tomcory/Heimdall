package de.tomcory.heimdall.ui.notification;

import android.app.IntentService;
import android.content.Intent;
import android.util.Log;

import androidx.annotation.Nullable;

import de.tomcory.heimdall.vpn.components.HeimdallVpnService;
import timber.log.Timber;

public class NotificationIntentService extends IntentService {

    private static final String TAG = NotificationIntentService.class.getSimpleName();

    public static final String STOP_VPN = "de.tomcory.heimdall.ui.notification.action.STOP_VPN";

    public NotificationIntentService() {
        super(NotificationIntentService.class.getSimpleName());
    }

    @Override
    protected void onHandleIntent(@Nullable Intent intent) {

        if (intent != null) {
            final String action = intent.getAction();
            if (STOP_VPN.equals(action)) {
                Timber.i("Handling intent: %s", action);
                stopVpn();
            } else {
                Timber.d("Unknown intent action: %s", action);
            }
        } else {
            Timber.d("Got null intent");
        }
    }

    private void stopVpn() {
        Intent serviceIntent = new Intent(this, HeimdallVpnService.class);
        serviceIntent.putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE);
        startService(serviceIntent);
//        if(stopService(new Intent(this, HeimdallVpnService.class))) {
//            Log.d(TAG, "Successfully stopped VPN service");
//        } else {
//            Log.d(TAG, "Failed to stop VPN service");
//        }
    }
}
