package de.tomcory.heimdall.net.flow;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.UdpPort;

public class Udp4Flow extends AbstractIp4Flow {

    private final boolean dns;

    Udp4Flow(IpV4Packet initialPacket, boolean persist, long sessionId) {
        super(initialPacket, persist, sessionId);
        dns = getRemotePort().valueAsInt() == 53;
    }

    public IpV4Packet buildPacket(byte[] rawPayload) {
        UdpPacket.Builder builder =  new UdpPacket.Builder()
                .srcAddr(getRemoteAddr())
                .dstAddr(getLocalAddr())
                .srcPort((UdpPort) remotePort)
                .dstPort((UdpPort) localPort)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(UnknownPacket.newPacket(rawPayload, 0, rawPayload.length).getBuilder());

        return buildIpv4Packet(builder);
    }

    public boolean isDns() {
        return dns;
    }
}
