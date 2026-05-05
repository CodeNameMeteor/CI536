package org.CI536.analyser.capture;

import org.CI536.analyser.parser.PacketDetails;
import org.CI536.analyser.parser.PacketExtractor;
import org.CI536.analyser.ui.PacketTableView;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

public class CaptureEngine {

    private static PcapHandle handle;
    private static PcapDumper dumper;
    private static final long[] PacketCount = {1};

    public static void startCapture(PcapNetworkInterface device, String saveFilePath) throws Exception {
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 50;

        System.out.println("Opening handle on: " + device.getDescription());
        handle = device.openLive(snapLen, mode, timeout);
        System.out.println("Handle opened successfully!");

        if (saveFilePath != null && !saveFilePath.isEmpty()) {
            dumper = handle.dumpOpen(saveFilePath);
            System.out.println("Saving capture to: " + saveFilePath);
        }


        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    java.sql.Timestamp ts = handle.getTimestamp();
                    PacketDetails details = PacketExtractor.ParseRawPacket(PacketCount[0], ipV4Packet, ts);

                    if (dumper != null) {
                        try {
                            dumper.dump(packet, ts);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }

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
            if (dumper != null && dumper.isOpen()) {
                dumper.close();
            }
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
    public static void loadOfflinePcap(String filePath) {
        try {
            System.out.println("Opening offline file: " + filePath);

            handle = Pcaps.openOffline(filePath);

            // Reset your counter when you load a new file
            PacketCount[0] = 1;

            // 1. Create the listener
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                        java.sql.Timestamp ts = handle.getTimestamp();

                        // Extract data
                        PacketDetails details = PacketExtractor.ParseRawPacket(PacketCount[0], ipV4Packet, ts);

                        // Push to the UI queue
                        PacketTableView.packetQueue.add(details);

                        // Increment counter
                        PacketCount[0] = PacketCount[0] + 1;
                    }
                }
            }; // <--- THIS is the bracket and semicolon that was missing!

            // 2. Loop through the file using the listener we just closed
            System.out.println("Reading packets...");
            handle.loop(-1, listener);

            System.out.println("Finished reading file.");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }
}