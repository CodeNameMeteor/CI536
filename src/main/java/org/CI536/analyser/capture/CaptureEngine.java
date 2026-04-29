package org.CI536.analyser.capture;

import org.CI536.analyser.parser.PacketDetails;
import org.CI536.analyser.parser.PacketExtractor;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.Scanner;

public class CaptureEngine {

    public static void startCapture() throws Exception {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();

        if (allDevs == null || allDevs.isEmpty()) {
            System.out.println("No network interfaces found. Ensure Npcap is installed and you have permissions.");
            return;
        }

        System.out.println("Available Network Interfaces:");
        for (int i = 0; i < allDevs.size(); i++) {
            PcapNetworkInterface device = allDevs.get(i);

            String description = device.getDescription() != null ? device.getDescription() : "No description available";
            System.out.printf("[%d] %s\n", i, description);

            if (!device.getAddresses().isEmpty()) {
                System.out.println("    IP: " + device.getAddresses().getFirst().getAddress().getHostAddress());
            }
        }

        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the number of the interface you want to sniff: ");
        int choice = scanner.nextInt();

        if (choice < 0 || choice >= allDevs.size()) {
            System.out.println("Invalid selection. Exiting.");
            return;
        }

        PcapNetworkInterface selectedDevice = allDevs.get(choice);
        System.out.println("\nYou selected: " + selectedDevice.getDescription());

        openHandle(selectedDevice);
    }

    private static void openHandle(PcapNetworkInterface device) throws Exception {
        int snapLen = 65536;

        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

        int timeout = 50;

        System.out.println("Opening handle...");
        PcapHandle handle = device.openLive(snapLen, mode, timeout);
        System.out.println("Handle opened successfully!");

        int packetCount = 0;
        boolean scanningActive = true;
        while (scanningActive) {
            try {
                Packet packet = handle.getNextPacketEx();
                if(System.in.available() > 0)
                {
                    scanningActive = false;
                }
                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    System.out.println("IP Packet " + packetCount + ":");
                    java.sql.Timestamp ts = handle.getTimestamp();
                    PacketDetails details = PacketExtractor.ParseRawPacket(ipV4Packet, ts);

                    System.out.println("Extracted: " + details.sourceIp() + " -> " + details.destinationIp() + " using " + details.protocol() + " at " + details.timestamp());
                    packetCount++;
                }

            } catch (java.util.concurrent.TimeoutException _) {
            } catch (java.io.EOFException e) {
                System.out.println("Reached end of capture file.");
                break;
            }
        }
        System.out.println("Packet Capture Over. Closing Handle :)");
        handle.close();
    }
}
