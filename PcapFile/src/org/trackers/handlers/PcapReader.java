package org.trackers.handlers;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

public class PcapReader {

	private static final String SAMPLE_FILE = "D:\\KSrour\\Eclipse-2022\\workspace\\PcapFile\\resources\\myfilecaptured.pcap";

	
	public static void main(String[] args) {
		// Initialize error buffer
		StringBuilder errbuf = new StringBuilder();

		// Open the pcap file
		Pcap pcap = Pcap.openOffline(SAMPLE_FILE, errbuf);

		// Check for errors
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}

		// Create a packet handler
		PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
			public void nextPacket(PcapPacket packet, String user) {
				// Create an Ip4 object
				Ip4 ip = new Ip4();

				// Check if the packet contains an IPv4 header
				if (packet.hasHeader(ip)) {
					// Extract the source and destination IP addresses
					byte[] srcIp = ip.source();
					byte[] dstIp = ip.destination();

					// Convert the IP addresses to strings
					String srcIpStr = org.jnetpcap.packet.format.FormatUtils.ip(srcIp);
					String dstIpStr = org.jnetpcap.packet.format.FormatUtils.ip(dstIp);

					// Print the IP addresses
					System.out.println("srcIP=" + srcIpStr + " dstIP=" + dstIpStr);
				}
			}
		};

		// Loop through the packets in the file
		pcap.loop(-1, handler, "");

		// Close the pcap handle
		pcap.close();
	}
}