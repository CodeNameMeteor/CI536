package org.CI536.analyser.parser;

public record PacketDetails(
        long packetNumber,
        String timestamp,
        String sourceIp,
        String destinationIp,
        String protocol,
        int length,
        String flags,
        String appData
) {
}