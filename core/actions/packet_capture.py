from scapy.sendrecv import sniff, wrpcap
from core.utils.host import get_wireless_mode, set_wireless_mode
from core.utils.directory import get_config

import asyncio
import pywifi
import logging

WIRELESS_MODE_MONITOR = "Monitoring"


def wifi_sniffing():
    config, config_file = get_config()

    nic_name = config.get("Network Interface", "name")
    wireless_mode = get_wireless_mode(interface=nic_name)

    # Set adapter to monitor mode
    if wireless_mode != WIRELESS_MODE_MONITOR:
        try:
            capture = sniff(iface=nic_name, count=50)
            wrpcap("test.pcap", capture)
        finally:
            set_wireless_mode(new_mode="Managed")


async def get_wifi_ssid(interface):
    logging.basicConfig(level=logging.WARNING)
    int_face = None

    wifi = pywifi.PyWiFi()

    for i in wifi.interfaces():
        if i.name() == interface:
            int_face = i

    if int_face:
        int_face.scan()
        await asyncio.sleep(5)

        profiles = filter(lambda p: p.ssid and not p.ssid.startswith("\x00\x00"), int_face.scan_results())

        return [{'ssid': profile.ssid, 'bssid': profile.bssid} for profile in profiles]
    else:
        return None
