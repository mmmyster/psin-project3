import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

public class arpSpoofingDetector {

	public static void main(String[] args) throws Exception {

		InetAddress addr = InetAddress.getLocalHost();
		System.out.println(addr);
		PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
		int snapLen = 65536;
		PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
		int timeout = 10;
		PcapHandle handle = nif.openLive(snapLen, mode, timeout);
		handle.loop(-1, new PacketListener() {
			@Override
			public void gotPacket(Packet packet) {
				// IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
				// Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
				// System.out.println(srcAddr);

				ArpPacket arp = packet.get(ArpPacket.class);
				Map<String, String> adress = new HashMap<>();

				if (arp != null) {
					System.out.println("ARP!");
					EthernetPacket eth = packet.get(EthernetPacket.class);
					System.out.print("Src MAC: " + eth.getHeader().getSrcAddr());
					System.out.println(" Dst MAC: " + eth.getHeader().getDstAddr());

					System.out.print("Sender MAC: " + arp.getHeader().getSrcHardwareAddr().toString());
					System.out.println(" Sender IP: " + arp.getHeader().getSrcProtocolAddr());
					System.out.println(" Type: " + arp.getHeader().getOperation().value());

					System.out.print("Target MAC: " + arp.getHeader().getDstHardwareAddr().toString());
					System.out.println(" Target IP: " + arp.getHeader().getDstProtocolAddr().getHostAddress());

					if (!detect(arp, adress))
						System.out.println("WARNING!");

					System.out.println();
				}
			}
		});
	}

	public static boolean detect(ArpPacket arp, Map<String, String> table) {
		String output = arp.toString();
		String ip = "";
		String mac = "";
		Scanner sc = new Scanner(output);

		while (sc.hasNext()) {

			String slovo = sc.next();

			if (slovo.equals("Sender")) {

				String s = sc.next();

				if (s.equals("MAC")) {
					sc.next();
					mac = sc.next();
				}

				if (s.equals("IP")) {
					sc.next();
					ip = sc.next();
				}
			}
		}

		if (table.containsKey(ip))
			if (!table.get(ip).equals(mac))
				return false;

			else
				table.put(ip, mac);

		return true;
	}
}
