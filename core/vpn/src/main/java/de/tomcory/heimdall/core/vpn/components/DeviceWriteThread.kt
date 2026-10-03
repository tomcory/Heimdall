package de.tomcory.heimdall.core.vpn.components

import android.os.Handler
import android.os.HandlerThread
import android.os.Message
import android.os.Process
import org.pcap4j.packet.IpPacket
import timber.log.Timber
import java.io.FileOutputStream
import java.io.IOException

class DeviceWriteThread(
    name: String,
    private val outputStream: FileOutputStream,
    private val handlerReadyListener: (handler: Handler) -> Unit
) : HandlerThread(
    name,
    Process.THREAD_PRIORITY_FOREGROUND
) {

    lateinit var handler: Handler
        private set

    init {
        Timber.d("Thread created")
    }

    override fun onLooperPrepared() {
        handler = object : Handler(looper) {
            override fun handleMessage(msg: Message) = handleMessageImpl(msg)
        }
        Timber.d("Looper prepared")
        // signal looper prepared
        handlerReadyListener.invoke(handler)
    }

    override fun quit(): Boolean {
        Timber.d("Thread shut down")
        return super.quit()
    }

    override fun quitSafely(): Boolean {
        Timber.d("Thread shut down")
        return super.quitSafely()
    }

    private fun handleMessageImpl(msg: Message) {
        // packets are usually pcap4j objects; ones built byte by byte (the ICMP errors of
        // WRITE_ICMP) come as raw bytes
        val rawData = when (val obj = msg.obj) {
            is IpPacket -> obj.rawData
            is ByteArray -> obj
            else -> {
                Timber.e("Got unknown message type: %s (what=%d, should be org.pcap4j.packet.IpPacket or ByteArray)", obj?.javaClass?.name, msg.what)
                return
            }
        }

        try {
            outputStream.write(rawData)
            outputStream.flush()
        } catch (e: IOException) {
            Timber.e(e, "Error writing packet of size ${rawData.size} to device")
        }
    }

    /**
     * Message codes (`Message.what`) used when posting packets to this thread's [handler]. They
     * are informational only (for logging and tests): [handleMessageImpl] writes any [IpPacket] it
     * receives to the device, regardless of the code.
     */
    companion object {
        /** A packet belonging to an existing TCP connection. */
        const val WRITE_TCP = 0

        /** A packet belonging to an existing UDP connection. */
        const val WRITE_UDP = 1

        /** A one-off packet not tied to any tracked connection, e.g. an RST answering a segment for an unknown flow. */
        const val WRITE_STRAY = 2

        /** An ICMP error built as raw bytes, e.g. the answer to a blocked QUIC datagram (docs/vpn-mitm-audit.md PKT-52). */
        const val WRITE_ICMP = 3
    }
}