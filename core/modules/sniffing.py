import argparse
from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import sniff, wrpcap
from core.utils.host import get_wireless_mode
from configparser import ConfigParser
import os


def capture_packets():
    wireless_mode = get_wireless_mode()
    if wireless_mode == "Monitoring":
        config_file = os.path.join(os.path.dirname(__file__), "../../config.ini")
        config = ConfigParser()
        config.read(config_file)

        nic_name = config.get("Network Interface", "name")

        capture = sniff(iface=nic_name, count=50)
        wrpcap("test.pcap", capture)

        # request = ARP()
        #
        # request.pdst = '10.0.0.1/24'
        # broadcast = Ether()
        #
        # broadcast.dst = 'ff:ff:ff:ff:ff:ff'
        #
        # request_broadcast = broadcast / request
        #
        # clients = srp(request_broadcast, timeout=10, verbose=1)[0]
        # for element in clients:
        #     print(element)
    else:
        print("Wireless adapter not in monitoring mode.")


capture_packets()
