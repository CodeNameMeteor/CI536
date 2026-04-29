package org.CI536.analyser.parser;

public record PacketDetails(
        String timestamp,
        String sourceIp,
        String destinationIp,
        String protocol,
        int length
) {
}
