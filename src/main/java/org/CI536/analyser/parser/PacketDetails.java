package org.CI536.analyser.parser;

public record PacketDetails(
        long count,
        String timestamp,
        String sourceIp,
        String destinationIp,
        String protocol,
        int length
) {
}
