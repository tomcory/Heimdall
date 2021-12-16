package de.tomcory.heimdall.net.vpn;

import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.os.Process;

import androidx.annotation.NonNull;

import org.pcap4j.packet.IpV4Packet;

import java.io.FileOutputStream;
import java.io.IOException;

import de.tomcory.heimdall.util.StringUtils;
import timber.log.Timber;

public class DeviceWriteThread extends HandlerThread {

    private Handler handler;
    private final FileOutputStream outputStream;

    DeviceWriteThread(@NonNull String name, @NonNull FileOutputStream outputStream) {
        super(name, Process.THREAD_PRIORITY_FOREGROUND);
        this.outputStream = outputStream;
        Timber.d("Thread created");
    }

    Handler getHandler() {
        return handler;
    }

    @Override
    protected void onLooperPrepared() {
        handler = new Handler(getLooper()) {
            @Override
            public void handleMessage(@NonNull Message msg) {

                if(!(msg.obj instanceof IpV4Packet)) {
                    Timber.e("Got unknown message type: " + msg.obj.getClass().getName() + " (should be org.pcap4j.packet.IpV4Packet)");
                    return;
                }

                IpV4Packet packet = (IpV4Packet) msg.obj;

                try {
                    outputStream.write(packet.getRawData());
                    outputStream.flush();

                } catch (IOException e) {
                    Timber.e(e, "Error writing packet to device %s", StringUtils.addressIn(packet));
                }
            }
        };

        // send signal that this thread is prepared
        Timber.d("Looper prepared");
        synchronized (HeimdallVpnService.threadReadyMonitor) {
            HeimdallVpnService.threadReadyMonitor.notifyAll();
        }
    }

    @Override
    public boolean quit() {
        Timber.d("Thread shut down");
        return super.quit();
    }

    @Override
    public boolean quitSafely() {
        Timber.d("Thread shut down");
        return super.quit();
    }
}
