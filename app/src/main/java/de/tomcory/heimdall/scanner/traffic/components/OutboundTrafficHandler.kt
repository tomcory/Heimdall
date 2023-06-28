package de.tomcory.heimdall.scanner.traffic.components

import android.os.Handler
import android.os.HandlerThread
import android.os.Message
import android.os.Process
import de.tomcory.heimdall.scanner.traffic.connection.transportLayer.TransportLayerConnection
import org.pcap4j.packet.IpPacket
import timber.log.Timber

class OutboundTrafficHandler(
    name: String,
    private val deviceWriter: Handler,
    private val componentManager: ComponentManager,
    private val handlerReadyListener: (handler: Handler) -> Unit
) : HandlerThread(
    name,
    Process.THREAD_PRIORITY_FOREGROUND
) {

    init {
        Timber.d("OutboundTrafficHandler created")
    }

    lateinit var handler: Handler private set

    override fun onLooperPrepared() {
        handler = object : Handler(looper) {
            override fun handleMessage(msg: Message) {
                handleMessageImpl(msg)
            }
        }
        Timber.d("OutboundTrafficHandler started")
        // signal looper prepared
        handlerReadyListener.invoke(handler)
    }

    /**
     * Handles the message based on its transport protocol.
     */
    private fun handleMessageImpl(msg: Message) {
        if((msg.what == 6 || msg.what == 17) && msg.obj is IpPacket) {
            val ipPacket = msg.obj as IpPacket
            TransportLayerConnection.getInstance(ipPacket, componentManager, deviceWriter)?.unwrapOutbound(ipPacket.payload)
        }
    }
}