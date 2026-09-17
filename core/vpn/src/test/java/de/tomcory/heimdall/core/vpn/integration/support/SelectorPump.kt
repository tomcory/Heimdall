package de.tomcory.heimdall.core.vpn.integration.support

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import java.nio.channels.Selector
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Test-only stand-in for [de.tomcory.heimdall.core.vpn.components.InboundTrafficHandler]'s
 * event loop. The integration harness uses a real [Selector] (registered to by real
 * TcpConnection/UdpConnection instances) but never starts the real Handler/Looper-based traffic
 * threads, so something still has to pump the selector and dispatch ready channels to their
 * attached [TransportLayerConnection] - this replicates that loop on a plain daemon thread.
 */
class SelectorPump(private val selector: Selector) {

    private val running = AtomicBoolean(false)
    private var thread: Thread? = null

    fun start() {
        if (!running.compareAndSet(false, true)) {
            return
        }
        thread = Thread({
            while (running.get()) {
                val selectedChannels = try {
                    selector.select(50)
                } catch (e: Exception) {
                    0
                }

                synchronized(ComponentManager.selectorMonitor) {
                    if (selectedChannels > 0) {
                        val iterator = selector.selectedKeys().iterator()
                        while (iterator.hasNext()) {
                            val key = iterator.next()
                            val attachment = key.attachment()
                            if (attachment is TransportLayerConnection) {
                                attachment.unwrapInbound()
                            }
                            iterator.remove()
                        }
                    }
                }
            }
        }, "test-selector-pump").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running.set(false)
        selector.wakeup()
        thread?.join(2000)
    }
}
