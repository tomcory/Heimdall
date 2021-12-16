package de.tomcory.heimdall.net.flow;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;

import java.util.ArrayList;

public class Tcp4Flow extends AbstractIp4Flow {

    private static final int MAX_TCP_SEGMENT_SIZE = 65495;

    private final long theirInitSeqNum;
    private final long ourInitSeqNum;
    private final short window;

    private long theirSeqNum;
    private long ourSeqNum;

    private int maxSegmentSize;

    Tcp4Flow(IpV4Packet initialPacket, boolean persist, long sessionId) {
        super(initialPacket, persist, sessionId);
        TcpPacket tcpPacket = (TcpPacket) initialPacket.getPayload();
        window = tcpPacket.getHeader().getWindow();
        theirInitSeqNum = tcpPacket.getHeader().getSequenceNumberAsLong();
        ourInitSeqNum = (long) (Math.random() * 0xFFFFFFF);
        theirSeqNum = theirInitSeqNum;
        ourSeqNum = ourInitSeqNum;
    }

    public void increaseTheirSeqNum(int increase) {
        theirSeqNum += increase;
    }

    public void increaseOurSeqNum(int increase) {
        ourSeqNum += increase;
    }

    public long getTheirSeqNum() {
        return theirSeqNum;
    }

    public long getOurSeqNum() {
        return ourSeqNum;
    }

    public long getTheirRelSeqNum() {
        return theirSeqNum - theirInitSeqNum;
    }

    public long getOurRelSeqNum() {
        return ourSeqNum - ourInitSeqNum;
    }

    private IpV4Packet buildPacket(boolean urg, boolean ack, boolean psh, boolean rst, boolean syn, boolean fin, byte[] rawPayload) {
        TcpPacket.Builder builder = new TcpPacket.Builder()
                .srcAddr(getRemoteAddr())
                .dstAddr(getLocalAddr())
                .srcPort((TcpPort) remotePort)
                .dstPort((TcpPort) localPort)
                .sequenceNumber((int) ourSeqNum)
                .acknowledgmentNumber((int) theirSeqNum)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .urg(urg)
                .ack(ack)
                .psh(psh)
                .rst(rst)
                .syn(syn)
                .fin(fin)
                .window(window)
                .urgentPointer((short) 0)
                .padding(new byte[0])
                .options(new ArrayList<>())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true);

        if(rawPayload.length > 0) {
            builder.payloadBuilder(UnknownPacket.newPacket(rawPayload, 0, rawPayload.length).getBuilder());
        }

        return buildIpv4Packet(builder);
    }

    public IpV4Packet buildSynAck() {
        return buildPacket(false, true, false, false, true, false, new byte[0]);
    }

    public IpV4Packet buildEmptyAck() {
        return buildPacket(false, true, false, false, false, false, new byte[0]);
    }

    public IpV4Packet buildDataAck(byte[] rawPayload) {
        return buildPacket(false, true, true, false, false, false, rawPayload);
    }

    public IpV4Packet buildRst() {
        return buildPacket(false, false, false, true, false, false, new byte[0]);
    }

    public IpV4Packet buildFin() {
        return buildPacket(false, false, false, false, false, true, new byte[0]);
    }

    public IpV4Packet buildFinAck() {
        return buildPacket(false, true, false, false, false, true, new byte[0]);
    }

    public static IpV4Packet buildRstForUnknownConnection(IpV4Packet strayPacket) {
        TcpPacket payload = (TcpPacket) strayPacket.getPayload();
        TcpPacket.Builder builder = new TcpPacket.Builder()
                .srcAddr(strayPacket.getHeader().getSrcAddr())
                .dstAddr(strayPacket.getHeader().getDstAddr())
                .srcPort(payload.getHeader().getDstPort())
                .dstPort(payload.getHeader().getSrcPort())
                .sequenceNumber(payload.getHeader().getAcknowledgmentNumber())
                .acknowledgmentNumber(payload.getHeader().getSequenceNumber())
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .urg(false)
                .ack(false)
                .psh(false)
                .rst(true)
                .syn(false)
                .fin(false)
                .window(payload.getHeader().getWindow())
                .urgentPointer((short) 0)
                .options(new ArrayList<>())
                .padding(new byte[0])
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(strayPacket.getHeader().getTos())
                .identification(strayPacket.getHeader().getIdentification())
                .reservedFlag(false)
                .dontFragmentFlag(false)
                .moreFragmentFlag(false)
                .fragmentOffset((short) 0)
                .ttl((byte) 8)
                .protocol(strayPacket.getHeader().getProtocol())
                .srcAddr(strayPacket.getHeader().getDstAddr())
                .dstAddr(strayPacket.getHeader().getSrcAddr())
                .options(new ArrayList<>())
                .padding(new byte[0])
                .payloadBuilder(builder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();
    }
}
