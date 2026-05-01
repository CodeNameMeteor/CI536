package org.CI536.analyser.capture;

import org.CI536.analyser.parser.PacketDetails;
import org.CI536.analyser.parser.PacketExtractor;
import org.CI536.analyser.ui.PacketTableView;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

public class CaptureEngine {

    private static PcapHandle handle;

    public static void startCapture(PcapNetworkInterface device) throws Exception {
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 50;
        final long[] PacketCount = {1};

        System.out.println("Opening handle on: " + device.getDescription());
        handle = device.openLive(snapLen, mode, timeout);
        System.out.println("Handle opened successfully!");


        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    java.sql.Timestamp ts = handle.getTimestamp();
                    PacketDetails details = PacketExtractor.ParseRawPacket(PacketCount[0], ipV4Packet, ts);

                    PacketTableView.packetQueue.add(details);
                    PacketCount[0] = PacketCount[0] + 1;
                }
            }
        };

        try {
            System.out.println("Listening for traffic...");
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            System.out.println("Capture interrupted.");
        } finally {
            System.out.println("Packet Capture Over. Closing Handle.");
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }

    public static void stopCapture() {
        if (handle != null && handle.isOpen()) {
            try {
                System.out.println("Breaking the capture loop...");
                handle.breakLoop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}