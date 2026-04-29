package org.CI536.analyser;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.net.Inet4Address;
import java.util.List;

public class TestCapture {

    public static void main(String[] args) {
        try {
            System.out.println("Starting Pcap4J Test...");

            // 1. Fetch devices
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs == null || allDevs.isEmpty()) {
                System.out.println("CRITICAL: No devices found. Is Npcap installed? Are you running as Administrator?");
                return;
            }

            // 2. Just grab the first active device for a quick test
            PcapNetworkInterface device = allDevs.get(1);
            System.out.println("Attempting to open: " + device.getDescription());

            // 3. Open the handle
            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 50;

            PcapHandle handle = device.openLive(snapLen, mode, timeout);
            System.out.println("SUCCESS! Handle opened. You have permission to sniff.");
            System.out.println("Listening for traffic...");
            int packetCount = 0;
            while (packetCount < 10) {
                try {
                    Packet packet = handle.getNextPacketEx();

                    // DANGER AVOIDED: Not all packets are IPv4!
                    // We must check if it contains IPv4 before doing anything.
                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                        String srcAddr = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
                        String dstAddr = ipV4Packet.getHeader().getDstAddr().getHostAddress();

                        System.out.println("Captured IP Packet: " + srcAddr + " -> " + dstAddr);
                        packetCount++;
                    }

                } catch (java.util.concurrent.TimeoutException e) {
                    // This is perfectly fine! It just means no packet arrived in the last 50ms.
                    // The loop will just restart and wait another 50ms.
                } catch (java.io.EOFException e) {
                    System.out.println("Reached end of capture file.");
                    break;
                }
            }
            // Close it immediately since we are just testing permissions
            handle.close();
            System.out.println("Handle closed safely.");

        } catch (PcapNativeException e) {
            System.err.println("\n--- PCAP NATIVE CRASH ---");
            System.err.println("This usually means a permissions issue or Npcap is missing.");
            e.printStackTrace();
        } catch (Throwable t) {
            System.err.println("\n--- UNKNOWN CRASH ---");
            t.printStackTrace();
        }
    }
}