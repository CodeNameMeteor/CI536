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

            int srcPort = tcpHeader.getSrcPort().valueAsInt();
            int dstPort = tcpHeader.getDstPort().valueAsInt();

            if (srcPort == 443 || dstPort == 443) {

                if (tcpPacket.getPayload() != null) {
                    byte[] payloadBytes = tcpPacket.getPayload().getRawData();

                    // Identify TLS type based on the first byte of the payload
                    if (payloadBytes.length > 0) {
                        int tlsType = payloadBytes[0] & 0xFF; // Convert byte to positive integer

                        if (tlsType == 22) { // 0x16 = Handshake
                            protocol = "TLSv1.2/1.3";

                            String sni = extractSniFromTls(payloadBytes);
                            if (sni != null && !sni.isEmpty()) {
                                appData = "Client Hello (SNI: " + sni + ")";
                            } else {
                                appData = "TLS Handshake Message";
                            }
                        }
                        else if (tlsType == 23) { // 0x17 = Application Data
                            protocol = "HTTPS";
                            appData = "Encrypted Application Data";
                        }
                        else if (tlsType == 21) { // 0x15 = Alert
                            protocol = "TLS Alert";
                            appData = "Encrypted Alert / Teardown";
                        }
                        else {
                            protocol = "TLS / HTTPS"; // Fallback
                            appData = "Encrypted Data";
                        }
                    }
                } else {
                    // If there is no payload, it's just a TCP ACK packet for the HTTPS connection
                    protocol = "TCP";
                }

            } else if (srcPort == 80 || dstPort == 80) {
                protocol = "HTTP";
            }
            appData += " " + tcpHeader.getSrcPort().valueAsString() + " > " + tcpHeader.getDstPort().valueAsString();

            if (tcpHeader.getSyn()) flags += "SYN ";
            if (tcpHeader.getAck()) flags += "ACK ";
            if (tcpHeader.getPsh()) flags += "PSH ";
            if (tcpHeader.getFin()) flags += "FIN ";
            if (tcpHeader.getRst()) flags += "RST ";

            flags = flags.trim().replace(" ", ", ");
            if (!flags.isEmpty()) flags = "[" + flags + "]"; appData += flags;

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

            appData = "[SRC: " + srcPort + ", DST: " + dstPort + "]";

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

                    appData += " Query: " + cleanDns;
                }
            }
        }

        return new PacketDetails(packetNumber, timeStr, srcAddr, dstAddr, protocol, length, appData);
    }

    private static String extractSniFromTls(byte[] payload) {
        try {
            //Ensure it's a TLS Handshake (0x16) and Client Hello (0x01)
            if (payload.length < 43 || payload[0] != 0x16 || payload[5] != 0x01) {
                return null;
            }

            // Hop over the fixed-length headers (Record, Handshake, Random)
            int offset = 43;

            // Hop over Session ID
            int sessionIdLen = payload[offset] & 0xFF;
            offset += 1 + sessionIdLen;

            // Hop over Cipher Suites
            int cipherLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            offset += 2 + cipherLen;

            // Hop over Compression Methods
            int compLen = payload[offset] & 0xFF;
            offset += 1 + compLen;

            int extTotalLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            offset += 2;
            int limit = Math.min(offset + extTotalLen, payload.length);

            while (offset + 4 <= limit) {
                int extType = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
                int extLen = ((payload[offset + 2] & 0xFF) << 8) | (payload[offset + 3] & 0xFF);
                offset += 4;

                if (extType == 0x0000 && offset + 5 < payload.length) { // Found SNI!
                    // Skip list length and type, grab the actual string length
                    int sniLen = ((payload[offset + 3] & 0xFF) << 8) | (payload[offset + 4] & 0xFF);

                    // Convert those specific bytes into a readable String
                    byte[] sniBytes = java.util.Arrays.copyOfRange(payload, offset + 5, offset + 5 + sniLen);
                    return new String(sniBytes);
                }
                offset += extLen;
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
}