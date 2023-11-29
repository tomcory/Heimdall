package de.tomcory.heimdall.core.vpn.connection.appLayer

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.vpn.components.ComponentManager
import de.tomcory.heimdall.core.vpn.connection.encryptionLayer.EncryptionLayerConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.pcap4j.packet.Packet
import timber.log.Timber

class HttpConnection(
    id: Long,
    encryptionLayer: EncryptionLayerConnection,
    componentManager: ComponentManager
) : AppLayerConnection(
    id,
    encryptionLayer,
    componentManager
) {

    private val chunkCache = mutableListOf<ByteArray>()
    private var overflowing = false
    private var chunked = false
    private var statedContentLength = -1
    private var remainingContentLength = -1

    init {
        if(id > 0) {
            Timber.d("http$id Creating HTTP connection to ${encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress}:${encryptionLayer.transportLayer.remotePort} (${encryptionLayer.transportLayer.remoteHost})")
        }
    }

    override fun unwrapOutbound(payload: ByteArray) {
        handleData(payload, true)
    }

    override fun unwrapOutbound(packet: Packet) {
        unwrapOutbound(packet.rawData)
    }

    override fun unwrapInbound(payload: ByteArray) {
        handleData(payload, false)
    }

    private fun handleData(payload: ByteArray, isOutbound: Boolean) {
        Timber.d("http$id Processing http ${if(isOutbound) "out" else "in"}:\n${payload.size} bytes")

        // distinguish between the first/only chuck and additional chunks
        if(!chunked && !overflowing) {

            // parse the raw bytes
            val message = payload.toString(Charsets.UTF_8)

            // the message is "officially" chunked only if this header is present
            chunked = message.contains("Transfer-Encoding: chunked")

            // messages can still overflow, which we can check by comparing the stated and actual content lengths
            overflowing = if(!chunked) {
                val lengthIndex = message.indexOf("Content-Length: ")
                statedContentLength = if(lengthIndex > 0) {
                    val endOfContentLength = message.indexOf("\r\n", lengthIndex + 16)
                    message.substring(lengthIndex + 16, endOfContentLength).toIntOrNull() ?: -1
                } else {
                    -1
                }

                // if there was no Content-Length header, we have to assume that there's no overflow since we cannot determine the intended length
                if(statedContentLength > 0) {
                    val bodyIndex = message.indexOf("\r\n\r\n") + 4
                    val actualContentLength = payload.size - bodyIndex
                    remainingContentLength = statedContentLength - actualContentLength
                    remainingContentLength > 0
                } else {
                    false
                }
            } else {
                false
            }


            // check whether the message is chunked or overflowing
            if(chunked || overflowing) {
                if(overflowing) {
                    Timber.w("http$id overflowing with $remainingContentLength of $statedContentLength remaining")
                }
                // if it is, cache this chunk and wait for more
                chunkCache.add(payload)
            } else {
                // otherwise persist the message
                persistMessage(message, isOutbound)
            }
        } else {
            // add the chunk to the cache
            chunkCache.add(payload)

            // we boldly assume that a message is overflowing XOR chunked - may the testers forgive us
            if(overflowing) {
                // check whether there's still content remaining after the current payload
                remainingContentLength -= payload.size
                Timber.w("http$id overflowing with $remainingContentLength of $statedContentLength remaining")
                if(remainingContentLength <= 0) {
                    // if there isn't, flatten the cache and persist the message
                    persistMessage(combineChunks().toString(Charsets.UTF_8), isOutbound)
                }
            } else {
                // check whether it's the last chunk
                //TODO: consider trailing headers
                val lines = payload.toString(Charsets.UTF_8).split("\r\n")
                if(lines.size >= 2 && (lines[lines.size - 2].trim().toIntOrNull(16) ?: -1) == 0) {
                    // if it is, flatten the cache, recombine the message and persist it
                    persistMessage(dechunkHttpMessage(combineChunks()), isOutbound)
                }
            }


        }

        // pass the payload back to the encryption layer
        if(isOutbound) {
            encryptionLayer.wrapOutbound(payload)
        } else {
            encryptionLayer.wrapInbound(payload)
        }
    }

    private fun persistMessage(message: String, isOutbound: Boolean) {
        // parse the three components of the message individually
        val statusLine = parseStatusLine(message, isOutbound)
        val headers = parseHeaders(message)
        val body = parseBody(message)

        // reset flags for reuse
        overflowing = false
        chunked = false
        statedContentLength = -1
        remainingContentLength = -1

        //Timber.e("http$id HTTP ${if(isOutbound) "REQUEST by" else "RESPONSE to"} ${encryptionLayer.transportLayer.appPackage} ${if(isOutbound) "to" else "from"} ${encryptionLayer.transportLayer.remoteHost}:\n${statusLine?.get(0)} ${statusLine?.get(1)}, ${statusLine?.get(2)}\n${headers.map { "${it.key}: ${it.value}" }.reduce { acc, s -> "$acc$s\n" }}> Content length: ${body.length}")

        CoroutineScope(Dispatchers.IO).launch {
            val id = if(isOutbound) {
                HeimdallDatabase.instance?.requestDao?.insert(
                    Request(
                        timestamp = System.currentTimeMillis(),
                        reqResId = id.toInt(),
                        headers = headers.map { "${it.key}: ${it.value}" }.reduce { acc, s -> "$acc$s\n" },
                        content = body,
                        contentLength = body.length,
                        method = statusLine?.get(0) ?: "",
                        remoteHost = encryptionLayer.transportLayer.remoteHost ?: "",
                        remotePath = statusLine?.get(1) ?: "",
                        remoteIp = encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: "",
                        remotePort = encryptionLayer.transportLayer.remotePort,
                        localIp = encryptionLayer.transportLayer.ipPacketBuilder.localAddress.hostAddress ?: "",
                        localPort = encryptionLayer.transportLayer.localPort,
                        initiatorId = encryptionLayer.transportLayer.appId ?: 0,
                        initiatorPkg = encryptionLayer.transportLayer.appPackage ?: ""
                    )
                )
            } else {
                HeimdallDatabase.instance?.responseDao?.insert(
                    Response(
                        timestamp = System.currentTimeMillis(),
                        reqResId = id.toInt(),
                        headers = headers.map { "${it.key}: ${it.value}" }.reduce { acc, s -> "$acc$s\n" },
                        content = body,
                        contentLength = body.length,
                        statusCode = statusLine?.get(1)?.toIntOrNull() ?: 0,
                        statusMsg = statusLine?.get(2) ?: "",
                        remoteHost = encryptionLayer.transportLayer.remoteHost ?: "",
                        remoteIp = encryptionLayer.transportLayer.ipPacketBuilder.remoteAddress.hostAddress ?: "",
                        remotePort = encryptionLayer.transportLayer.remotePort,
                        localIp = encryptionLayer.transportLayer.ipPacketBuilder.localAddress.hostAddress ?: "",
                        localPort = encryptionLayer.transportLayer.localPort,
                        initiatorId = encryptionLayer.transportLayer.appId ?: 0,
                        initiatorPkg = encryptionLayer.transportLayer.appPackage ?: ""
                    )
                )
            }

            Timber.e("http$id HTTP ${if(isOutbound) "REQUEST" else "RESPONSE"} insertion returned id ${id?.first()}")
        }
        //TODO: build entity and persist, that could be done in a coroutine
    }

    private fun parseStatusLine(message: String, isOutbound: Boolean): List<String>? {
        val endOfStatusLine = message.indexOf("\r\n")

        if(endOfStatusLine < 0) {
            Timber.e("http$id Invalid status line, no newline found")
            Timber.e("http$id $message")
            return null
        }

        val statusLine = message.substring(0, endOfStatusLine)

        val parts = statusLine.split(" ", limit = 3)

        if (parts.size < 3) {
            Timber.e("http$id Invalid status line: $statusLine")
            return null
        }

        if(!isOutbound && parts[1].toIntOrNull() == null) {
            Timber.e("http$id Invalid status code in status line: $statusLine")
            return null
        }

        return listOf(parts[0], parts[1], parts[2])
    }

    private fun parseHeaders(message: String): Map<String, String> {
        val headersIndex = message.indexOf("\r\n") + 2
        val bodyIndex = message.indexOf("\r\n\r\n")

        if(headersIndex < 0 || bodyIndex < 0) {
            Timber.e("http$id parseHeaders Invalid HTTP message, no headers found")
            return emptyMap()
        }

        val headerBlock = message.substring(headersIndex, bodyIndex)

        val headerLines = headerBlock.split("\r\n")

        return headerLines.associate { line ->
            val (name, value) = line.split(": ", limit = 2)
            name to value
        }
    }

    private fun parseBody(message: String): String {
        val bodyIndex = message.indexOf("\r\n\r\n") + 4

        if(bodyIndex < 0) {
            Timber.e("http$id parseBody Invalid HTTP message, no chunks found")
            return ""
        }

        return message.substring(bodyIndex)
    }

    private fun dechunkHttpMessage(chunkedMessage: ByteArray): String {
        val chunkedMessageStr = String(chunkedMessage, Charsets.UTF_8)

        val headersIndex = chunkedMessageStr.indexOf("\r\n") + 2
        val chunkedBodyIndex = chunkedMessageStr.indexOf("\r\n\r\n") + 4

        if(headersIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no headers found")
            return ""
        }

        if(chunkedBodyIndex < 0) {
            Timber.e("http$id dechunkHttpMessage Invalid HTTP message, no chunks found")
            return ""
        }

        val statusAndHeaders = chunkedMessageStr.substring(0, chunkedBodyIndex)
        val chunkedBody = chunkedMessageStr.substring(chunkedBodyIndex)

        val chunks = chunkedBody.split("\r\n")
        val dechunkedBody = StringBuilder()

        var i = 0
        while (i < chunks.size) {
            // Chunks are in format: <chunk size in hex>\r\n<chunk data>\r\n
            val chunkSize = chunks[i++].toInt(16)
            if (chunkSize == 0) {
                // This is the last chunk
                break
            }

            dechunkedBody.append(chunks[i++])
        }

        return "$statusAndHeaders$dechunkedBody"
    }

    private fun combineChunks(): ByteArray {
        val totalSize = chunkCache.sumOf { it.size }
        val result = ByteArray(totalSize)
        var position = 0
        for (bytes in chunkCache) {
            bytes.copyInto(result, position)
            position += bytes.size
        }
        // at this point we're done with the cache and can clear it for reuse
        chunkCache.clear()
        return result
    }
}