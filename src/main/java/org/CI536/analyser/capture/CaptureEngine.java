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

    // Keep the handle at the class level so we can access it to stop the capture later
    private static PcapHandle handle;

    // Notice we removed the Scanner! The UI will pass the selected device directly into this method.
    public static void startCapture(PcapNetworkInterface device) throws Exception {
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 50;
        final long[] PacketCount = {1};

        System.out.println("Opening handle on: " + device.getDescription());
        handle = device.openLive(snapLen, mode, timeout);
        System.out.println("Handle opened successfully!");

        // 1. THIS IS YOUR LISTENER
        // It sits in the background and fires automatically whenever a packet arrives
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    java.sql.Timestamp ts = handle.getTimestamp();
                    PacketDetails details = PacketExtractor.ParseRawPacket(PacketCount[0], ipV4Packet, ts);

                    // Parse the packet

                    // PUSH TO THE JAVAFX UI QUEUE!
                    PacketTableView.packetQueue.add(details);
                    PacketCount[0] = PacketCount[0] + 1;
                }
            }
        };

        // 2. START THE INFINITE CAPTURE LOOP
        try {
            System.out.println("Listening for traffic...");
            // -1 tells Pcap4J to loop forever until we explicitly tell it to stop
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            System.out.println("Capture interrupted.");
        } finally {
            // This runs automatically when we break the loop
            System.out.println("Packet Capture Over. Closing Handle.");
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }

    // 3. THE KILL SWITCH FOR YOUR UI
    public static void stopCapture() {
        if (handle != null && handle.isOpen()) {
            try {
                System.out.println("Breaking the capture loop...");
                handle.breakLoop(); // This forces handle.loop() to safely exit
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}