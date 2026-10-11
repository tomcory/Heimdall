package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import org.pcap4j.packet.Packet
import timber.log.Timber
import java.io.ByteArrayOutputStream

/**
 * DNS over a stream: TCP to port 53, or DNS over TLS (port 853) once decrypted.
 * Each message is preceded by its length in two bytes (RFC 1035
 * section 4.2.2), a message may be split across segments, and one segment may carry several.
 *
 * Every byte is passed on unchanged and at once in both directions. The responses are also
 * reassembled on the side to fill the DNS cache; one that cannot be read is skipped.
 */
class DnsStreamConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager
) : AppLayerConnection(
    id,
    encryptionLayer,
    componentManager
) {

    init {
        if(id > 0) {
            Timber.d("dns$id Creating DNS stream connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }

    /** Inbound bytes that do not yet make up a whole message. Only touched on the inbound path. */
    private val pending = ByteArrayOutputStream()

    /** Set when the stream turned out not to be framed DNS; nothing more is read from it then. */
    private var opaque = false

    override fun unwrapOutbound(payload: ByteArray) {
        encryptionLayer.wrapOutbound(payload)
    }

    override fun unwrapOutbound(packet: Packet) {
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        if (!opaque) {
            readMessages(payload)
        }
        encryptionLayer.wrapInbound(payload)
    }

    private fun readMessages(payload: ByteArray) {
        pending.write(payload)
        val buffer = pending.toByteArray()
        var offset = 0
        while (buffer.size - offset >= 2) {
            val length = ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
            if (length == 0) {
                // no DNS message is empty: this is not framed DNS
                giveUp()
                return
            }
            if (buffer.size - offset - 2 < length) {
                break
            }
            val message = buffer.copyOfRange(offset + 2, offset + 2 + length)
            if (!DnsConnection.cacheAnswers(componentManager, message)) {
                Timber.w("dns$id Could not read a DNS message of $length bytes, skipping it")
            }
            offset += 2 + length
        }
        pending.reset()
        if (offset < buffer.size) {
            // the start of the next message; at most 65535 bytes plus the length
            pending.write(buffer, offset, buffer.size - offset)
        }
    }

    private fun giveUp() {
        Timber.w("dns$id Stream is not framed DNS, no longer reading it")
        opaque = true
        pending.reset()
    }
}
