package de.tomcory.heimdall.core.vpn.components

import android.os.Handler
import android.os.HandlerThread
import android.os.Message
import android.os.Process
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
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

            val connection = try {
                TransportLayerConnection.getInstance(ipPacket, componentManager, deviceWriter)
            } catch (e: Throwable) {
                Timber.e(e, "Uncaught exception while creating a connection for outbound traffic, dropping the packet")
                return
            }

            try {
                connection?.unwrapOutbound(ipPacket.payload)
            } catch (e: Throwable) {
                Timber.e(e, "Uncaught exception while processing outbound traffic, closing the connection")
                try {
                    connection?.closeHard()
                } catch (closeException: Throwable) {
                    Timber.e(closeException, "Error while closing connection after an uncaught exception")
                }
            }
        }
    }
}