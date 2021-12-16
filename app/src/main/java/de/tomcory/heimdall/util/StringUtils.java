package de.tomcory.heimdall.util;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TransportPacket;

import de.tomcory.heimdall.net.flow.AbstractIp4Flow;

public class StringUtils {


    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String address(AbstractIp4Flow connection) {
        return "[" + connection.getRemoteAddr().getHostAddress() + ":" + connection.getRemotePort().valueAsInt() + "]";
    }

    public static String addressOut(IpV4Packet ipPacket) {
        TransportPacket.TransportHeader transportHeader = (TransportPacket.TransportHeader) ipPacket.getPayload().getHeader();
        return "[" + ipPacket.getHeader().getDstAddr().getHostAddress() + ":" + transportHeader.getDstPort().valueAsInt() + "]";
    }

    public static String addressIn(IpV4Packet ipPacket) {
        TransportPacket.TransportHeader transportHeader = (TransportPacket.TransportHeader) ipPacket.getPayload().getHeader();
        return "[" + ipPacket.getHeader().getSrcAddr().getHostAddress() + ":" + transportHeader.getSrcPort().valueAsInt() + "]";
    }

    public static boolean isValidIpAddress(String address) {
        String[] bytes = address.split(".");
        if(bytes.length != 4) {
            return false;
        }

        for(String b : bytes) {
            try {
                int value = Integer.parseInt(b);
                if(value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }
}
