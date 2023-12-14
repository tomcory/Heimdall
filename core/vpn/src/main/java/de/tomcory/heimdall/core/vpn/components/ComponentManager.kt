package de.tomcory.heimdall.core.vpn.components

import android.content.Context
import android.net.VpnService
import android.system.ErrnoException
import android.system.Os
import de.tomcory.heimdall.core.vpn.R
import de.tomcory.heimdall.core.vpn.cache.ConnectionCache
import de.tomcory.heimdall.core.vpn.metadata.AppFinder
import de.tomcory.heimdall.core.vpn.metadata.DnsCache
import de.tomcory.heimdall.core.vpn.metadata.TlsPassthroughCache
import de.tomcory.heimdall.core.vpn.mitm.Authority
import de.tomcory.heimdall.core.vpn.mitm.CertificateSniffingMitmManager
import de.tomcory.heimdall.core.vpn.mitm.VpnComponentLaunchException
import de.tomcory.heimdall.core.util.Trie
import org.pcap4j.packet.IllegalRawDataException
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.namednumber.TcpPort
import org.pcap4j.packet.namednumber.UdpPort
import timber.log.Timber
import java.io.*
import java.nio.channels.Selector

/**
 * Manages the lifecycle of the traffic-handling components of the VPN.
 *
 * @throws VpnComponentLaunchException if the component initialisation failed.
 */
class ComponentManager(
    private val outboundStream: FileInputStream,
    private val inboundStream: FileOutputStream,
    val vpnService: VpnService?,
    val doMitm: Boolean = false,
    val maxPacketSize: Int = 16413,
    private val trackerTrie: Trie<String> = Trie {
        it.split(
            "."
        ).reversed()
    }
) {

    private var devicePollThread: DevicePollThread? = null
    private var deviceWriteThread: DeviceWriteThread? = null
    private var outboundTrafficHandler: OutboundTrafficHandler? = null
    private var inboundTrafficHandler: InboundTrafficHandler? = null

    private val interrupter: FileDescriptor
    private val interrupted: FileDescriptor

    val appFinder = AppFinder(vpnService)

    val dnsCache = DnsCache()

    val tlsPassthroughCache = TlsPassthroughCache()

    //TODO: get strings from config/secure
    val authority = Authority.getDefaultInstance(vpnService?.applicationContext)

    // set up the man-in-the-middle manager
    val mitmManager: CertificateSniffingMitmManager = CertificateSniffingMitmManager(authority)

    // set up the NIO selector that is used to poll the outgoing sockets for incoming packets
    val selector: Selector = try {
        Selector.open()
    } catch (e: IOException) {
        throw VpnComponentLaunchException("Error opening selector", e)
    }

    init {
        // set up the pipes that are used to poll the VPN interface for new outgoing packets
        val pipes = try {
            Os.pipe()
        } catch (e: ErrnoException) {
            throw VpnComponentLaunchException("Error getting pipes from OS", e)
        }
        interrupter = pipes[0]
        interrupted = pipes[1]

        // initialise the pcap4j configuration now to improve performance during traffic handling
        initialisePcap4j()

        // prepare the trie of tracking hosts used to label traffic
        vpnService?.let {
            Timber.d("Building tracking hosts trie")
            populateTrieFromRawFile(it.applicationContext, R.raw.adhosts, trackerTrie)
        }

        /*
         * Create and start the traffic handler threads. Since the threads rely on handlers to pass messages to each other
         * and the handler is instantiated asynchronously within the threads, this needs to be wrapped in callbacks.
         * The threads are created and started in the following order:
         * 1 - DeviceWriteThread
         * 2 - Inbound- & OutboundTrafficHandler (both with the DeviceWriteThread's handler)
         * 3 - DevicePollThread (with the OutboundTrafficHandler's handler)
         */
        deviceWriteThread = DeviceWriteThread(
            "DeviceWriteThread",
            inboundStream
        ) { deviceWriter ->
            inboundTrafficHandler =
                InboundTrafficHandler(
                    "InboundTrafficHandler",
                    this
                )
            outboundTrafficHandler =
                OutboundTrafficHandler(
                    "OutboundTrafficHandler",
                    deviceWriter,
                    this
                ) { outHandler ->
                    devicePollThread =
                        DevicePollThread(
                            "DevicePollThread",
                            outboundStream,
                            interrupter,
                            outHandler
                        )
                    devicePollThread?.start()
                    Timber.d("Traffic handlers initialised")
                }
            inboundTrafficHandler?.start()
            outboundTrafficHandler?.start()
        }
        deviceWriteThread?.start()
    }

    fun stopComponents() {
        // closing the interrupter pipe stops the DevicePollThread's polling
        try {
            Os.close(interrupter)
        } catch (e: ErrnoException) {
            Timber.w(e, "Error closing interrupter pipe")
        }

        outboundTrafficHandler?.quitSafely()
        inboundTrafficHandler?.interrupt()
        deviceWriteThread?.quitSafely()

        try {
            outboundStream.close()
            inboundStream.close()
        } catch (e: IOException) {
            Timber.w(e, "Error closing VPN interface streams")
        }

        ConnectionCache.closeAllAndClear()
    }

    /**
     * Initialises the pcap4 library components used to parse and build packets.
     *
     * @throws VpnComponentLaunchException
     */
    private fun initialisePcap4j() {
        Timber.d("Initialising pcap4j configuration")

        // this is just the raw dump of a random TCP SYN packet used for the packet parser
        val rawPacket = byteArrayOf(
            0x45, 0x00, 0x00, 0x3C, 0x15, 0xD4.toByte(), 0x40, 0x00, 0x40, 0x06, 0xC1.toByte(), 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x6D, 0x14, 0x8B.toByte(), 0x63, 0x00, 0x00,
            0x00, 0x00, 0xA0.toByte(), 0x02, 0xFF.toByte(), 0xFF.toByte(), 0xB1.toByte(), 0x50, 0x00, 0x00,
            0x02, 0x04, 0x05, 0xB4.toByte(), 0x04, 0x02, 0x08, 0x0A, 0x00, 0xF8.toByte(), 0x9E.toByte(), 0xB7.toByte(), 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06
        )

        // by building a packet from raw data we kick of the slow pcap4j initial properties loading process now instead of when the actual first packet is processed
        val parsedPacket: IpV4Packet = try {
            IpV4Packet.newPacket(rawPacket, 0, rawPacket.size)
        } catch (e: IllegalRawDataException) {
            throw VpnComponentLaunchException("Error initialising pcap4j packet parser", e)
        }

        // using packet builders for the first time is also slow, so we do it now

        // build a TCP packet
        try {
            TcpPacket.Builder()
                .srcAddr(parsedPacket.header.srcAddr)
                .dstAddr(parsedPacket.header.dstAddr)
                .srcPort(TcpPort.getInstance(12345))
                .dstPort(TcpPort.HTTPS)
                .sequenceNumber(1)
                .acknowledgmentNumber(1)
                .dataOffset(5.toByte())
                .reserved(0.toByte())
                .urg(false)
                .ack(true)
                .psh(false)
                .rst(false)
                .syn(true)
                .fin(false)
                .window(8)
                .urgentPointer(0.toShort())
                .padding(ByteArray(0))
                .options(ArrayList())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true)
        } catch (e: Exception) {
            throw VpnComponentLaunchException("Error initialising pcap4j TCP packet builder", e)
        }

        // build a UDP packet
        try {
            UdpPacket.Builder()
                .srcAddr(parsedPacket.header.srcAddr)
                .dstAddr(parsedPacket.header.dstAddr)
                .srcPort(UdpPort.getInstance(12345))
                .dstPort(UdpPort.DOMAIN)
                .correctChecksumAtBuild(true)
                .build()
        } catch (e: Exception) {
            throw VpnComponentLaunchException("Error initialising pcap4j UDP packet builder", e)
        }

        Timber.d("Completed pcap4j configuration")
    }

    private fun populateTrieFromRawFile(context: Context, resId: Int, trie: Trie<String>) {
        val startTime = System.currentTimeMillis()

        val inputStream = context.resources.openRawResource(resId)
        val reader = BufferedReader(InputStreamReader(inputStream))
        var lineCounter = 0

        reader.use { r ->
            r.forEachLine { line ->
                trie.insert(line, line)
                lineCounter++
            }
        }

        reader.close()

        Timber.d("Inserted $lineCounter entries into trie in ${System.currentTimeMillis() - startTime}ms")
    }

    fun labelConnection(remoteHost: String) = trackerTrie.search(remoteHost) != null

    companion object {
        val selectorMonitor: Any = Any()
    }
}