package de.tomcory.heimdall.core.vpn.components

import android.os.Process
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import timber.log.Timber
import java.io.IOException

class InboundTrafficHandler(
    name: String,
    private val componentManager: ComponentManager
) : Thread(name) {

    init {
        Process.setThreadPriority(Process.THREAD_PRIORITY_FOREGROUND)
        Timber.d("InboundTrafficHandler created")
    }

    override fun run() {
        Timber.d("InboundTrafficHandler started")
        var selectedChannels: Int

        while (!interrupted()) {
            selectedChannels = 0

            // A thread that registers a channel holds the monitor while it does so, after
            // waking the selector up. Passing through the monitor here keeps this thread from
            // going back into select(), which would block the registration, until it is done.
            // The selected keys are processed outside the monitor: holding it for that long
            // made every new connection wait for all pending inbound work
            // (docs/vpn-mitm-audit.md PKT-41).
            synchronized(ComponentManager.selectorMonitor) { }

            try {
                selectedChannels = componentManager.selector.select()
            } catch (e: IOException) {
                Timber.e(e, "Error during selection process")
            }

            if (selectedChannels > 0) {
                val iterator = componentManager.selector.selectedKeys().iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    val attachment = key.attachment()
                    if (attachment == null) {
                        Timber.e("Channel has null attachment")
                        key.cancel()
                        continue
                    }
                    if (attachment is TransportLayerConnection) {
                        try {
                            attachment.unwrapInbound()
                        } catch (e: Throwable) {
                            Timber.e(e, "Uncaught exception while processing inbound traffic, closing the connection")
                            try {
                                attachment.closeHard()
                            } catch (closeException: Throwable) {
                                Timber.e(closeException, "Error while closing connection after an uncaught exception")
                            }
                        }
                    } else {
                        Timber.e("Invalid attachment %s", attachment.javaClass)
                    }
                    iterator.remove()
                }
            }
        }
        Timber.d("Thread shut down")
    }
}