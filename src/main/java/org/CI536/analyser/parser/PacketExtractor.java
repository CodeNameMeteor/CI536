package org.CI536.analyser.parser;

import org.pcap4j.packet.IpV4Packet;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;

public class PacketExtractor {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

    public static PacketDetails ParseRawPacket(long count, IpV4Packet packet, Timestamp timestamp)
    {
        String timeStr = TIME_FORMAT.format(timestamp);
        String srcAddr = packet.getHeader().getSrcAddr().getHostAddress();
        String dstAddr = packet.getHeader().getDstAddr().getHostAddress();
        String protocol = packet.getHeader().getProtocol().name();
        int length = packet.length();
        //String something = packet.getHeader().
        return new PacketDetails(count, timeStr, srcAddr, dstAddr, protocol, length);
    }
}
