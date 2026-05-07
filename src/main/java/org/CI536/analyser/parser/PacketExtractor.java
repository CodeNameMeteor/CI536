package org.CI536.analyser.parser;

import org.pcap4j.packet.*;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;

public class PacketExtractor {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

    public static PacketDetails ParseRawPacket(long packetNumber, Packet packet, Timestamp timestamp) {

        String timeStr = TIME_FORMAT.format(timestamp);
        String srcAddr = "Unknown";
        String dstAddr = "Unknown";
        String protocol = "Unknown";
        int length = packet.length();
        String flags = "";

        String appData = "";

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ip4 = packet.get(IpV4Packet.class);
            srcAddr = ip4.getHeader().getSrcAddr().getHostAddress();
            dstAddr = ip4.getHeader().getDstAddr().getHostAddress();
            protocol = ip4.getHeader().getProtocol().name();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ip6 = packet.get(IpV6Packet.class);
            srcAddr = ip6.getHeader().getSrcAddr().getHostAddress();
            dstAddr = ip6.getHeader().getDstAddr().getHostAddress();
            protocol = ip6.getHeader().getProtocol().name();
        } else {
            return null;
        }

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();

            // 1. GET THE PORTS
            int srcPort = tcpHeader.getSrcPort().valueAsInt();
            int dstPort = tcpHeader.getDstPort().valueAsInt();

            // 2. SMART PROTOCOL LABELING BASED ON PORTS
            if (srcPort == 443 || dstPort == 443) {
                protocol = "HTTPS";
            } else if (srcPort == 80 || dstPort == 80) {
                protocol = "HTTP";
            }

            // 3. EXTRACT TCP FLAGS
            if (tcpHeader.getSyn()) flags += "SYN ";
            if (tcpHeader.getAck()) flags += "ACK ";
            if (tcpHeader.getPsh()) flags += "PSH ";
            if (tcpHeader.getFin()) flags += "FIN ";
            if (tcpHeader.getRst()) flags += "RST ";

            flags = flags.trim().replace(" ", ", ");
            if (!flags.isEmpty()) flags = "[" + flags + "]";

            if (tcpPacket.getPayload() != null) {
                byte[] payloadBytes = tcpPacket.getPayload().getRawData();
                String payloadString = new String(payloadBytes);

                if (payloadString.startsWith("GET ") ||
                        payloadString.startsWith("POST ") ||
                        payloadString.startsWith("HTTP/1.")) {

                    String[] lines = payloadString.split("\r\n");
                    if (lines.length > 0) {
                        appData = lines[0];
                        protocol = "HTTP";
                    }
                }
            }
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();

            int srcPort = udpHeader.getSrcPort().valueAsInt();
            int dstPort = udpHeader.getDstPort().valueAsInt();

            flags = "[SRC: " + srcPort + ", DST: " + dstPort + "]";

            if (srcPort == 53 || dstPort == 53) {
                protocol = "DNS";

                if (udpPacket.getPayload() != null) {
                    byte[] payloadBytes = udpPacket.getPayload().getRawData();
                    StringBuilder safeText = new StringBuilder();

                    for (byte b : payloadBytes) {
                        if (b >= 32 && b <= 126) {
                            safeText.append((char) b);
                        } else {
                            safeText.append(".");
                        }
                    }


                    String cleanDns = safeText.toString().replaceAll("\\.{2,}", ".");

                    if (cleanDns.startsWith(".")) cleanDns = cleanDns.substring(1);

                    appData = "Query: " + cleanDns;
                }
            }
        }

        return new PacketDetails(packetNumber, timeStr, srcAddr, dstAddr, protocol, length, flags, appData);
    }
}