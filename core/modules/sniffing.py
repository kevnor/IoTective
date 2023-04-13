from scapy.sendrecv import sniff, wrpcap
from core.utils.host import get_wireless_mode, set_wireless_mode
from configparser import ConfigParser
import os


def capture_packets():
    wireless_mode = get_wireless_mode()
    config_file = os.path.join(os.path.dirname(__file__), "../../config.ini")
    config = ConfigParser()
    config.read(config_file)

    nic_name = config.get("Network Interface", "name")

    # Set adapter to monitor mode
    if wireless_mode != "Monitoring":
        set_wireless_mode()

    capture = sniff(iface=nic_name, count=50)
    wrpcap("test.pcap", capture)

    # Set adapter to managed mode
    set_wireless_mode(new_mode="Managed")

capture_packets()
