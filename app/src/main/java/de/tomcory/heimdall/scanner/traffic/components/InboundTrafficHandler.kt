package de.tomcory.heimdall.scanner.traffic.components

import android.os.Process
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import timber.log.Timber
import java.io.IOException

class InboundTrafficHandler(
    name: String,
    val manager: ComponentManager
) : Thread(name) {

    init {
        Process.setThreadPriority(Process.THREAD_PRIORITY_FOREGROUND)
        Timber.d("Thread created")
    }

    override fun run() {
        Timber.d("Thread started")
        var selectedChannels: Int

        while (!interrupted()) {
            selectedChannels = 0
            try {
                selectedChannels = manager.selector.select()
            } catch (e: IOException) {
                Timber.e(e, "Error during selection process")
            }

            synchronized(ComponentManager.selectorMonitor) {
                if (selectedChannels > 0) {
                    val iterator = manager.selector.selectedKeys().iterator()
                    while (iterator.hasNext()) {
                        val key = iterator.next()
                        val attachment = key.attachment()
                        if (attachment == null) {
                            Timber.e("Channel has null attachment")
                            key.cancel()
                            continue
                        }
                        if (attachment is TransportLayerConnection) {
                            attachment.unwrapInbound()
                        } else {
                            Timber.e("Invalid attachment %s", attachment.javaClass)
                        }
                        iterator.remove()
                    }
                }
            }
        }
        Timber.d("Thread shut down")
    }
}