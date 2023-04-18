from scapy.sendrecv import sniff, wrpcap
from core.utils.sniffer import get_wireless_mode, set_wireless_mode
from core.utils.directory import get_config


def wifi_sniffing():
    config, config_file = get_config()

    nic_name = config.get("Network Interface", "name")
    wireless_mode = get_wireless_mode(interface=nic_name)

    # Set adapter to monitor mode
    if wireless_mode != "Monitoring":
        set_wireless_mode()

    capture = sniff(iface=nic_name, count=50)
    wrpcap("test.pcap", capture)

    # Set adapter to managed mode
    set_wireless_mode(new_mode="Managed")
