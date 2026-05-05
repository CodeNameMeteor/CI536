package org.CI536.analyser.capture;

import org.CI536.analyser.parser.PacketDetails;
import org.CI536.analyser.parser.PacketExtractor;
import org.CI536.analyser.ui.PacketTableView;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

public class CaptureEngine {

    private static final long[] PacketCount = {1};
    private static PcapHandle handle;
    private static PcapDumper dumper;
    private static java.io.File tempCaptureFile;

    public static void startCapture(PcapNetworkInterface device) throws Exception {
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 50;

        handle = device.openLive(snapLen, mode, timeout);
        PacketCount[0] = 1;

        tempCaptureFile = java.io.File.createTempFile("javapcap_temp", ".pcap");
        tempCaptureFile.deleteOnExit();

        dumper = handle.dumpOpen(tempCaptureFile.getAbsolutePath());
        System.out.println("Buffering raw packets to hidden temp file...");

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                java.sql.Timestamp ts = handle.getTimestamp();

                if (dumper != null) {
                    try {
                        dumper.dump(packet, ts);
                        dumper.flush();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
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
            if (dumper != null && dumper.isOpen()) {
                dumper.close(); // IMPORTANT: Close the dumper so the temp file finishes saving!
            }
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }

    public static void saveCaptureToFile(java.io.File destination) {
        if (tempCaptureFile != null && tempCaptureFile.exists()) {
            try {
                java.nio.file.Files.copy(tempCaptureFile.toPath(), destination.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                System.out.println("Capture saved successfully to: " + destination.getAbsolutePath());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No capture data to save!");
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
            PacketCount[0] = 1;
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    java.sql.Timestamp ts = handle.getTimestamp();
                    if (dumper != null) {
                        try {
                            dumper.dump(packet, ts);
                            dumper.flush();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                        PacketDetails details = PacketExtractor.ParseRawPacket(PacketCount[0], ipV4Packet, ts);
                        PacketTableView.packetQueue.add(details);
                        PacketCount[0] = PacketCount[0] + 1;
                    }
                }
            };
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