package org.CI536.analyser.parser;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket; // Import this!
import org.pcap4j.packet.UdpPacket;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;

public class PacketExtractor {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

    public static PacketDetails ParseRawPacket(long packetNumber, IpV4Packet packet, Timestamp timestamp) {

        String timeStr = TIME_FORMAT.format(timestamp);
        String srcAddr = packet.getHeader().getSrcAddr().getHostAddress();
        String dstAddr = packet.getHeader().getDstAddr().getHostAddress();
        String protocol = packet.getHeader().getProtocol().name();
        int length = packet.length();

        String flags = "";

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();


            if (tcpHeader.getSyn()) flags += "SYN ";
            if (tcpHeader.getAck()) flags += "ACK ";
            if (tcpHeader.getPsh()) flags += "PSH ";
            if (tcpHeader.getFin()) flags += "FIN ";
            if (tcpHeader.getRst()) flags += "RST ";

            flags = flags.trim().replace(" ", ", ");
            if (!flags.isEmpty()) {
                flags = "[" + flags + "]";
            }
        }
        if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();

            flags += "SRC: " + udpHeader.getSrcPort();
            flags += "DST: " + udpHeader.getDstPort();
        }
        return new PacketDetails(packetNumber, timeStr, srcAddr, dstAddr, protocol, length, flags);
    }
}