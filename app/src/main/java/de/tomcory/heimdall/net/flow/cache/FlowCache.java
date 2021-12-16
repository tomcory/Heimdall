package de.tomcory.heimdall.net.flow.cache;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TransportPacket;

import java.util.HashMap;

import de.tomcory.heimdall.net.flow.AbstractIp4Flow;
import timber.log.Timber;

public class FlowCache {

    private static final FlowCache cache = new FlowCache();

    private final HashMap<Long, AbstractIp4Flow> flows = new HashMap<>();

    public static AbstractIp4Flow findFlow(IpV4Packet ipV4Packet) {
        return cache.flows.get(getKey(ipV4Packet));
    }

    public static void addFlow(AbstractIp4Flow flow) {
        AbstractIp4Flow oldFlow = cache.flows.put(getKey(flow), flow);
        if(oldFlow != null) {
            Timber.e("flow overwritten: " + oldFlow.toString() + " " + flow.toString());
        }
    }

    public static void removeFlow(AbstractIp4Flow flow) {
        cache.flows.remove(getKey(flow));
    }

    private static long getKey(IpV4Packet ipPacket) {
        byte[] remoteAddr = ipPacket.getHeader().getDstAddr().getAddress();

        TransportPacket transportPacket = (TransportPacket) ipPacket.getPayload();
        int localPort = transportPacket.getHeader().getSrcPort().valueAsInt();
        int remotePort = transportPacket.getHeader().getDstPort().valueAsInt();
        byte protocol = ipPacket.getHeader().getProtocol().value();

        return ((long) protocol & 0xFFL) << 48 | ((long) remoteAddr[0] & 0xFFL) << 40 | ((long) remoteAddr[1] & 0xFFL) << 32 | ((long) remoteAddr[2] & 0xFFL) << 24 | ((long) remoteAddr[3] & 0xFFL) << 16 | ((long) localPort & 0xFFL) << 8 | ((long) remotePort & 0xFFL);
    }

    private static long getKey(AbstractIp4Flow flow) {
        byte[] remoteAddr = flow.getRemoteAddr().getAddress();
        int localPort = flow.getLocalPort().valueAsInt();
        int remotePort = flow.getRemotePort().valueAsInt();
        byte protocol = flow.getTransportProtocol().value();

        return ((long) protocol & 0xFFL) << 48 | ((long) remoteAddr[0] & 0xFFL) << 40 | ((long) remoteAddr[1] & 0xFFL) << 32 | ((long) remoteAddr[2] & 0xFFL) << 24 | ((long) remoteAddr[3] & 0xFFL) << 16 | ((long) localPort & 0xFFL) << 8 | ((long) remotePort & 0xFFL);
    }

    public static void closeAllandClear() {
        for(AbstractIp4Flow flow : cache.flows.values()) {
            flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CLOSED);
        }
        cache.flows.clear();
    }
}
