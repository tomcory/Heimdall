package de.tomcory.heimdall.core.vpn.integration.support

import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.UnknownPacket
import org.pcap4j.packet.factory.PacketFactories
import org.pcap4j.packet.namednumber.IpNumber
import org.pcap4j.packet.namednumber.IpVersion
import org.pcap4j.packet.namednumber.NotApplicable
import org.pcap4j.packet.namednumber.TcpPort
import org.pcap4j.packet.namednumber.UdpPort
import java.net.Inet4Address

/**
 * Shared packet construction helpers for the core:vpn integration test suite.
 *
 * [warmUpPcap4j] replicates [de.tomcory.heimdall.core.vpn.components.ComponentManager.initialisePcap4j]'s
 * one-time factory warm-up (see feedback_pcap4j memory): pcap4j's static packet factories throw NPEs the
 * first time a Builder is used unless a packet has already been parsed once via newPacket(). Production
 * code relies on this warm-up having already run (TcpConnection/IpV4PacketBuilder use Builders for every
 * outbound-to-device packet), so every integration test in this package must call it once before
 * constructing any TcpConnection/UdpConnection.
 */
object PacketFixtures {

    @Volatile
    private var warmedUp = false

    @Synchronized
    fun warmUpPcap4j() {
        if (warmedUp) {
            return
        }

        // raw dump of a TCP SYN packet, identical to ComponentManager.initialisePcap4j()
        val rawPacket = byteArrayOf(
            0x45, 0x00, 0x00, 0x3C, 0x15, 0xD4.toByte(), 0x40, 0x00, 0x40, 0x06, 0xC1.toByte(), 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x6D, 0x14, 0x8B.toByte(), 0x63, 0x00, 0x00,
            0x00, 0x00, 0xA0.toByte(), 0x02, 0xFF.toByte(), 0xFF.toByte(), 0xB1.toByte(), 0x50, 0x00, 0x00,
            0x02, 0x04, 0x05, 0xB4.toByte(), 0x04, 0x02, 0x08, 0x0A, 0x00, 0xF8.toByte(), 0x9E.toByte(), 0xB7.toByte(), 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06
        )

        val parsedPacket: IpV4Packet = IpV4Packet.newPacket(rawPacket, 0, rawPacket.size)

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

        UdpPacket.Builder()
            .srcAddr(parsedPacket.header.srcAddr)
            .dstAddr(parsedPacket.header.dstAddr)
            .srcPort(UdpPort.getInstance(12345))
            .dstPort(UdpPort.DOMAIN)
            .correctChecksumAtBuild(true)
            .build()

        warmedUp = true
    }

    private fun zeroTos(): IpV4Packet.IpV4Tos {
        return PacketFactories
            .getFactory(IpV4Packet.IpV4Tos::class.java, NotApplicable::class.java)
            .newInstance(byteArrayOf(0), 0, 1)
    }

    fun buildIpV4Packet(
        srcAddr: Inet4Address,
        dstAddr: Inet4Address,
        protocol: IpNumber,
        payloadBuilder: Packet.Builder,
        identification: Int = 0
    ): IpV4Packet {
        return IpV4Packet.Builder()
            .version(IpVersion.IPV4)
            .ihl(5.toByte())
            .tos(zeroTos())
            .identification(identification.toShort())
            .reservedFlag(false)
            .dontFragmentFlag(false)
            .moreFragmentFlag(false)
            .fragmentOffset(0.toShort())
            .ttl(64.toByte())
            .protocol(protocol)
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .options(ArrayList())
            .padding(ByteArray(0))
            .payloadBuilder(payloadBuilder)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .build()
    }

    fun buildTcpSegment(
        srcAddr: Inet4Address,
        dstAddr: Inet4Address,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
        ack: Int,
        ackFlag: Boolean = true,
        synFlag: Boolean = false,
        finFlag: Boolean = false,
        pshFlag: Boolean = false,
        rstFlag: Boolean = false,
        window: Int = 65535,
        payload: ByteArray = ByteArray(0)
    ): TcpPacket.Builder {
        val builder = TcpPacket.Builder()
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .srcPort(TcpPort(srcPort.toShort(), ""))
            .dstPort(TcpPort(dstPort.toShort(), ""))
            .sequenceNumber(seq)
            .acknowledgmentNumber(ack)
            .dataOffset(5.toByte())
            .reserved(0.toByte())
            .urg(false)
            .ack(ackFlag)
            .psh(pshFlag)
            .rst(rstFlag)
            .syn(synFlag)
            .fin(finFlag)
            .window(window.toShort())
            .urgentPointer(0.toShort())
            .padding(ByteArray(0))
            .options(ArrayList())
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .paddingAtBuild(true)
        if (payload.isNotEmpty()) {
            builder.payloadBuilder(UnknownPacket.newPacket(payload, 0, payload.size).builder)
        }
        return builder
    }

    /** Builds the IPv4+TCP SYN packet used to open a new synthetic "device-initiated" TCP connection. */
    fun buildTcpSynPacket(
        localAddr: Inet4Address,
        localPort: Int,
        remoteAddr: Inet4Address,
        remotePort: Int,
        seq: Int = 0
    ): IpV4Packet {
        val tcp = buildTcpSegment(
            srcAddr = localAddr,
            dstAddr = remoteAddr,
            srcPort = localPort,
            dstPort = remotePort,
            seq = seq,
            ack = 0,
            ackFlag = false,
            synFlag = true
        )
        return buildIpV4Packet(localAddr, remoteAddr, IpNumber.TCP, tcp)
    }

    /** Builds an IPv4+TCP packet representing data (or a bare flag) sent by the synthetic "device" client. */
    fun buildTcpDataPacket(
        localAddr: Inet4Address,
        localPort: Int,
        remoteAddr: Inet4Address,
        remotePort: Int,
        seq: Int,
        ack: Int,
        payload: ByteArray = ByteArray(0),
        ackFlag: Boolean = true,
        pshFlag: Boolean = payload.isNotEmpty(),
        finFlag: Boolean = false,
        rstFlag: Boolean = false
    ): IpV4Packet {
        val tcp = buildTcpSegment(
            srcAddr = localAddr,
            dstAddr = remoteAddr,
            srcPort = localPort,
            dstPort = remotePort,
            seq = seq,
            ack = ack,
            ackFlag = ackFlag,
            pshFlag = pshFlag,
            finFlag = finFlag,
            rstFlag = rstFlag,
            payload = payload
        )
        return buildIpV4Packet(localAddr, remoteAddr, IpNumber.TCP, tcp)
    }

    fun buildUdpSegment(
        srcAddr: Inet4Address,
        dstAddr: Inet4Address,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): UdpPacket.Builder {
        return UdpPacket.Builder()
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .srcPort(UdpPort(srcPort.toShort(), ""))
            .dstPort(UdpPort(dstPort.toShort(), ""))
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(UnknownPacket.newPacket(payload, 0, payload.size).builder)
    }

    /** Builds the IPv4+UDP packet used to open a new synthetic "device-initiated" UDP "connection" (e.g. a DNS query). */
    fun buildUdpPacket(
        localAddr: Inet4Address,
        localPort: Int,
        remoteAddr: Inet4Address,
        remotePort: Int,
        payload: ByteArray
    ): IpV4Packet {
        val udp = buildUdpSegment(localAddr, remoteAddr, localPort, remotePort, payload)
        return buildIpV4Packet(localAddr, remoteAddr, IpNumber.UDP, udp)
    }

    /**
     * Variant that embeds an already-typed nested [Packet.Builder] (e.g. a `DnsPacket.Builder`) as the UDP
     * payload, instead of wrapping raw bytes in an [UnknownPacket]. AppLayerConnection's dispatch logic
     * checks the *runtime type* of the nested packet (`packet is DnsPacket`) on the outbound leg, so this
     * is required to exercise the DNS dispatch path regardless of which UDP port is actually used.
     */
    fun buildUdpSegment(
        srcAddr: Inet4Address,
        dstAddr: Inet4Address,
        srcPort: Int,
        dstPort: Int,
        payloadBuilder: Packet.Builder
    ): UdpPacket.Builder {
        return UdpPacket.Builder()
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .srcPort(UdpPort(srcPort.toShort(), ""))
            .dstPort(UdpPort(dstPort.toShort(), ""))
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(payloadBuilder)
    }

    fun buildUdpPacket(
        localAddr: Inet4Address,
        localPort: Int,
        remoteAddr: Inet4Address,
        remotePort: Int,
        payloadBuilder: Packet.Builder
    ): IpV4Packet {
        val udp = buildUdpSegment(localAddr, remoteAddr, localPort, remotePort, payloadBuilder)
        return buildIpV4Packet(localAddr, remoteAddr, IpNumber.UDP, udp)
    }
}
