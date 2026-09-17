package de.tomcory.heimdall.core.vpn.integration

import android.os.Message
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.connection.transportLayer.TransportLayerConnection
import de.tomcory.heimdall.core.vpn.integration.support.ComponentManagerFixtures
import de.tomcory.heimdall.core.vpn.integration.support.FakeClientTlsDriver
import de.tomcory.heimdall.core.vpn.integration.support.FakeTlsServer
import de.tomcory.heimdall.core.vpn.integration.support.PacketFixtures
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDatabaseConnector
import de.tomcory.heimdall.core.vpn.integration.support.RecordingDeviceWriter
import de.tomcory.heimdall.core.vpn.integration.support.SelectorPump
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pcap4j.packet.IpPacket
import org.pcap4j.packet.TcpPacket
import java.net.Inet4Address
import java.net.InetAddress
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLEngineResult

/**
 * End-to-end integration test for the real-MITM happy path: a synthetic "device" TCP connection
 * completes a real TLS handshake against TlsConnection's dynamically-generated client-facing
 * SSLEngine, while TlsConnection's server-facing SSLEngine simultaneously completes a real TLS
 * handshake against [FakeTlsServer]. A single HTTPS request/response is then exchanged through
 * both encrypted legs and the decrypted content is verified at every observation point: the
 * plaintext that arrives at FakeTlsServer, the plaintext recorded in the database, and the
 * plaintext that the fake client driver decrypts out of the traffic written back to "the device".
 */
class TlsMitmHttpFlowTest {

    private lateinit var fakeTlsServer: FakeTlsServer
    private lateinit var pump: SelectorPump
    private lateinit var dbConnector: RecordingDatabaseConnector

    private val localAddr = InetAddress.getByName("10.0.0.30") as Inet4Address
    private val remoteAddr = InetAddress.getByName("127.0.0.1") as Inet4Address
    private val localPort = 44001
    private val hostname = "example.com"

    @Before
    fun setup() {
        PacketFixtures.warmUpPcap4j()
        ConnectionCache.closeAllAndClear()
        dbConnector = RecordingDatabaseConnector()
        fakeTlsServer = FakeTlsServer(hostname)
    }

    @After
    fun teardown() {
        if (::pump.isInitialized) pump.stop()
        fakeTlsServer.close()
        ConnectionCache.closeAllAndClear()
    }

    private fun extractTcpPayload(message: Message): ByteArray {
        val ipPacket = message.obj as IpPacket
        val tcpPacket = ipPacket.payload as TcpPacket
        return tcpPacket.payload?.rawData ?: ByteArray(0)
    }

    private fun awaitAtLeast(deviceWriter: RecordingDeviceWriter, count: Int, timeoutMs: Long = 5000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && deviceWriter.sentMessages.size < count) {
            Thread.sleep(20)
        }
    }

    @Test
    fun `single HTTPS request-response completes through a real MITM TLS handshake`() {
        val requestBytes = AtomicReference<ByteArray?>(null)
        val canned = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"

        fakeTlsServer.acceptOnce { socket ->
            val buf = ByteArray(8192)
            val read = socket.inputStream.read(buf)
            if (read > 0) {
                requestBytes.set(buf.copyOf(read))
            }
            socket.outputStream.write(canned.toByteArray())
            socket.outputStream.flush()
        }

        val componentManager = ComponentManagerFixtures.buildTestComponentManager(
            keyStoreDir = createTempDir(),
            databaseConnector = dbConnector
        )
        pump = SelectorPump(componentManager.selector)
        pump.start()

        val deviceWriter = RecordingDeviceWriter()

        // 3-way TCP handshake
        val synPacket = PacketFixtures.buildTcpSynPacket(localAddr, localPort, remoteAddr, fakeTlsServer.port)
        val connection = TransportLayerConnection.getInstance(synPacket, componentManager, deviceWriter.handler)
        connection?.unwrapOutbound(synPacket.payload)

        awaitAtLeast(deviceWriter, 1)
        assertTrue("expected a SYN-ACK", deviceWriter.sentMessages.isNotEmpty())
        println("DBG test: got SYN-ACK, total messages=${deviceWriter.sentMessages.size}")

        val ackPacket = PacketFixtures.buildTcpDataPacket(
            localAddr, localPort, remoteAddr, fakeTlsServer.port, seq = 1, ack = 1, pshFlag = false
        )
        connection?.unwrapOutbound(ackPacket.payload)

        var nextMessageIndex = deviceWriter.sentMessages.size
        var deviceSeq = 1

        val driver = FakeClientTlsDriver(hostname, fakeTlsServer.port)

        fun sendToProduction(bytes: ByteArray) {
            val packet = PacketFixtures.buildTcpDataPacket(
                localAddr, localPort, remoteAddr, fakeTlsServer.port,
                seq = deviceSeq, ack = 1, payload = bytes
            )
            deviceSeq += bytes.size
            connection?.unwrapOutbound(packet.payload)
        }

        // --- TLS handshake: drive the fake client engine against TlsConnection's clientSSLEngine ---
        val clientHello = driver.wrap()
        assertNotNull("driver failed to produce a ClientHello", clientHello)
        println("DBG test: sending ClientHello (${clientHello!!.size} bytes)")
        sendToProduction(clientHello)

        var loopIter = 0
        val handshakeDeadline = System.currentTimeMillis() + 20000
        while (System.currentTimeMillis() < handshakeDeadline && !driver.isHandshakeFinished()) {
            if (deviceWriter.sentMessages.size > nextMessageIndex) {
                val chunk = extractTcpPayload(deviceWriter.sentMessages[nextMessageIndex])
                println("DBG test: loop#${loopIter++}, msg#${nextMessageIndex} chunk=${chunk.size}B driverStatus=${driver.handshakeStatus}")
                nextMessageIndex++
                if (chunk.isNotEmpty()) {
                    driver.unwrap(chunk)
                }
            } else {
                Thread.sleep(10)
            }

            if (driver.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                val out = driver.wrap()
                if (out != null && out.isNotEmpty()) {
                    println("DBG test: sending driver wrap (${out.size} bytes)")
                    sendToProduction(out)
                }
            }
        }
        println("DBG test: handshake loop ended, finished=${driver.isHandshakeFinished()}, status=${driver.handshakeStatus}, totalMsgs=${deviceWriter.sentMessages.size}")
        assertTrue("client-facing TLS handshake never completed", driver.isHandshakeFinished())

        // --- application data: send an HTTPS request through the now-established session ---
        val httpRequest = "GET /test HTTP/1.1\r\nHost: $hostname\r\n\r\n"
        val encryptedRequest = driver.wrap(httpRequest.toByteArray())
        assertNotNull("failed to encrypt the HTTP request", encryptedRequest)
        sendToProduction(encryptedRequest!!)

        val requestDeadline = System.currentTimeMillis() + 10000
        while (System.currentTimeMillis() < requestDeadline && requestBytes.get() == null) {
            Thread.sleep(20)
        }
        assertNotNull("FakeTlsServer never received a decrypted HTTP request", requestBytes.get())
        assertEquals(httpRequest, String(requestBytes.get()!!))

        // --- wait for the encrypted response to come back to "the device" and decrypt it ---
        val responseDeadline = System.currentTimeMillis() + 10000
        var decryptedResponse: ByteArray? = null
        while (System.currentTimeMillis() < responseDeadline && decryptedResponse == null) {
            if (deviceWriter.sentMessages.size > nextMessageIndex) {
                val chunk = extractTcpPayload(deviceWriter.sentMessages[nextMessageIndex])
                nextMessageIndex++
                if (chunk.isNotEmpty()) {
                    decryptedResponse = driver.unwrap(chunk)
                }
            } else {
                Thread.sleep(20)
            }
        }
        assertNotNull("never received the encrypted HTTP response back from production", decryptedResponse)
        assertEquals(canned, String(decryptedResponse!!))

        // --- persistence assertions ---
        val persistDeadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < persistDeadline && (dbConnector.requests.isEmpty() || dbConnector.responses.isEmpty())) {
            Thread.sleep(20)
        }
        assertEquals(1, dbConnector.requests.size)
        assertEquals("GET", dbConnector.requests[0].method)
        assertEquals("/test", dbConnector.requests[0].remotePath)
        assertEquals(1, dbConnector.responses.size)
        assertEquals(200, dbConnector.responses[0].statusCode)
        assertEquals("Hello, world!", dbConnector.responses[0].content)

        // --- certificate assertion: the dynamically-generated leaf cert must mirror FakeTlsServer's CN ---
        val peerCert = driver.engine.session.peerCertificates[0] as X509Certificate
        val cn = Regex("CN=([^,]+)").find(peerCert.subjectX500Principal.name)?.groupValues?.get(1)
        assertEquals(hostname, cn)
    }
}
