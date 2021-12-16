package de.tomcory.heimdall.net.flow;

import androidx.annotation.NonNull;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.Port;

import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.util.ArrayList;

import de.tomcory.heimdall.net.flow.cache.FlowCache;
import de.tomcory.heimdall.persistence.database.TrafficDatabase;
import de.tomcory.heimdall.persistence.database.entity.Flow;
import de.tomcory.heimdall.util.StringUtils;
import timber.log.Timber;

public abstract class AbstractIp4Flow {

    private static final String TAG = "AbstractIp4Flow";

    private static final int ETHERNET_FRAME = 1500;
    private static final int HEADER_LENGTH = 40;

    public enum FlowStatus {
        NEW, // SYN received, channel not yet created
        CONNECTING, // channel created, not yet connected
        CONNECTED, // channel connected
        CLOSING, // FIN received, channel not yet closed
        CLOSED, // channel closed
        ABORTED // error state
    }

    private FlowStatus flowStatus = FlowStatus.NEW;
    private long flowId;
    private final long sessionId;

    // corresponding database entity
    private Flow databaseEntity = new Flow();

    // global headers that are applied to all packets
    private final IpV4Packet.IpV4Tos tos;
    private final short identification;
    private final IpNumber transportProtocol;
    private final Inet4Address localAddr;
    private final Inet4Address remoteAddr;
    final Port localPort;
    final Port remotePort;

    // ByteBuffers used for NIO channel writes/reads (separate to allow parallel read/write)
    private final ByteBuffer outBuffer = ByteBuffer.allocate(ETHERNET_FRAME);
    private final ByteBuffer inBuffer = ByteBuffer.allocate(ETHERNET_FRAME - HEADER_LENGTH);

    // SelectionKey of the corresponding NIO channel
    private SelectionKey selectionKey;

    private final long timestampCreated;

    public static AbstractIp4Flow getInstance(IpV4Packet initialPacket, boolean persist, long sessionId) throws UnsupportedProtocolException {

        IpNumber protocol = initialPacket.getHeader().getProtocol();

        AbstractIp4Flow flow;
        if(protocol.equals(IpNumber.TCP)) {
            flow = new Tcp4Flow(initialPacket, persist, sessionId);
        } else if(protocol.equals(IpNumber.UDP)) {
            flow = new Udp4Flow(initialPacket, persist, sessionId);
        } else {
            throw new UnsupportedProtocolException();
        }
        return flow;
    }

    AbstractIp4Flow(IpV4Packet initialPacket, boolean persist, long sessionId) {

        timestampCreated = System.currentTimeMillis();

        this.sessionId = sessionId;

        IpV4Packet.IpV4Header initialHeader = initialPacket.getHeader();
        tos = initialHeader.getTos();
        identification = initialHeader.getIdentification();
        transportProtocol = initialHeader.getProtocol();
        localAddr = initialHeader.getSrcAddr();
        remoteAddr = initialHeader.getDstAddr();

        TransportPacket initialPayload = (TransportPacket) initialPacket.getPayload();
        localPort = initialPayload.getHeader().getSrcPort();
        remotePort = initialPayload.getHeader().getDstPort();

        // adding the flow to the FlowCache allows it to be accessed easily when its packets are handled
        FlowCache.addFlow(this);

        // persist the flow in the database
        if(persist && remotePort.valueAsInt() != 53) {

            long start = System.currentTimeMillis();
            databaseEntity = new Flow(sessionId, start, 4, transportProtocol.name(), remotePort.valueAsInt(), true, remotePort.valueAsInt() == 443);
            flowId = TrafficDatabase.getInstance().getFlowDao().insertSync(databaseEntity);
            databaseEntity.flowId = flowId;
            long stop = System.currentTimeMillis();
            Timber.d("insertion took " + (stop - start) + "ms, FlowID is " + flowId);
        }
    }

    IpV4Packet buildIpv4Packet(Packet.Builder payloadBuilder) {
        return new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(tos)
                .identification(identification)
                .reservedFlag(false)
                .dontFragmentFlag(false)
                .moreFragmentFlag(false)
                .fragmentOffset((short) 0)
                .ttl((byte) 64)
                .protocol(transportProtocol)
                .srcAddr(remoteAddr)
                .dstAddr(localAddr)
                .options(new ArrayList<>())
                .padding(new byte[0])
                .payloadBuilder(payloadBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();
    }

    public long getFlowId() {
        return flowId;
    }

    public Flow getDatabaseEntity() {
        return databaseEntity;
    }

    public Inet4Address getLocalAddr() {
        return localAddr;
    }

    public Inet4Address getRemoteAddr() {
        return remoteAddr;
    }

    public Port getLocalPort() {
        return localPort;
    }

    public Port getRemotePort() {
        return remotePort;
    }

    public SelectionKey getSelectionKey() {
        return selectionKey;
    }

    public void setSelectionKey(SelectionKey selectionKey) {
        this.selectionKey = selectionKey;
    }

    public ByteBuffer getOutBuffer() {
        return outBuffer;
    }

    public ByteBuffer getInBuffer() {
        return inBuffer;
    }

    public long getRelativeTimestamp() {
        return System.currentTimeMillis() - timestampCreated;
    }

    public synchronized FlowStatus getFlowStatus() {
        return flowStatus;
    }

    public synchronized void setFlowStatus(FlowStatus flowStatus) {
        Timber.d("FlowStatus change: " + this.flowStatus.name() + " -> " + flowStatus.name() + " " + StringUtils.address(this));
        this.flowStatus = flowStatus;

        if(this.flowStatus == FlowStatus.CLOSED || this.flowStatus == FlowStatus.ABORTED) {
            Timber.d("Flow " + this.flowStatus.name().toLowerCase() + " " + StringUtils.address(this));

            // persist the duration of non-DNS flows
            if(remotePort.valueAsInt() != 53) {
                databaseEntity.isActive = false;
                databaseEntity.duration = System.currentTimeMillis() - timestampCreated;
                TrafficDatabase.getInstance().addFlowToUpdateCache(databaseEntity);
            }
        }
    }

    public synchronized void setHostname(String hostname) {
        databaseEntity.hostname = hostname;
    }

    public synchronized void setAppPackage(String appPackage) {
        databaseEntity.appPackage = appPackage;
    }

    public boolean isTls() {
        return databaseEntity.isTls;
    }

    public IpNumber getTransportProtocol() {
        return transportProtocol;
    }

    public void setTls(boolean tls) {
        databaseEntity.isTls = tls;
        TrafficDatabase.getInstance().addFlowToUpdateCache(databaseEntity);
    }

    public void increaseStats(boolean direction, int packetLength, int payloadLength) {
        if(direction) {
            databaseEntity.totalBytesOut += packetLength;
            databaseEntity.payloadBytesOut += payloadLength;
            databaseEntity.packetsOut++;
        } else {
            databaseEntity.totalBytesIn += packetLength;
            databaseEntity.payloadBytesIn += payloadLength;
            databaseEntity.packetsIn++;
        }
        TrafficDatabase.getInstance().addFlowToUpdateCache(databaseEntity);
    }

    @Override
    @NonNull
    public String toString() {
        return "AbstractIp4Flow{" +
                "flowStatus=" + flowStatus +
                ", id=" + flowId +
                ", transportProtocol=" + transportProtocol +
                ", localAddr=" + localAddr.getHostAddress() +
                ", remoteAddr=" + remoteAddr.getHostAddress() +
                ", localPort=" + localPort.valueAsInt() +
                ", remotePort=" + remotePort.valueAsInt() +
                ", timestampCreated=" + timestampCreated +
                '}';
    }

    public static class UnsupportedProtocolException extends Exception {
        UnsupportedProtocolException() {
            super();
        }
    }
}
