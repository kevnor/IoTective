import argparse
from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import sniff
from core.utils.host import check_wireless_mode

# def parse():
# # Parse command line arguments
# parser = argparse.ArgumentParser()
# parser.add_argument("pcap_file", help="Path to the pcap file")
# args = parser.parse_args()
#
# # Load the pcap file and extract Wi-Fi packets
# packets = rdpcap(args.pcap_file)
# wifi_packets = [p for p in packets if p.haslayer(Dot11)]
#
# # Extract unique MAC addresses from the Wi-Fi packets
# mac_addresses = set()
# for packet in wifi_packets:
#     mac_addresses.add(packet.addr2)
#
# # Print the list of MAC addresses
# print("The following devices were identified:")
# for mac in mac_addresses:
#     print(mac)


def capture_packets():
    wireless_mode = check_wireless_mode()
    if wireless_mode == "Monitoring":
        capture = sniff()

        request = ARP()

        request.pdst = '10.0.0.1/24'
        broadcast = Ether()

        broadcast.dst = 'ff:ff:ff:ff:ff:ff'

        request_broadcast = broadcast / request

        clients = srp(request_broadcast, timeout=10, verbose=1)[0]
        for element in clients:
            print(element)
    else:
        print("Wireless adapte")


capture_packets()
