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
    else:
        print("Wireless adapter not in monitoring mode.")


capture_packets()
