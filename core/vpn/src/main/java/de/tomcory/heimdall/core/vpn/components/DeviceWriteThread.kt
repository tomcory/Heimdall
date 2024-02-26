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
        if (msg.obj !is IpPacket) {
            Timber.e("Got unknown message type: %s (should be org.pcap4j.packet.IpV4Packet)", msg.obj.javaClass.name)
            return
        }

        val packet = msg.obj as IpPacket

        try {
            outputStream.write(packet.rawData)
            outputStream.flush()
        } catch (e: IOException) {
            Timber.e(e, "Error writing packet of size ${packet.length()} to device")
        }
    }

    companion object {
        const val WRITE_TCP = 0
        const val WRITE_UDP = 1
    }
}