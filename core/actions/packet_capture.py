from scapy.sendrecv import sniff, wrpcap
from core.utils.host import get_wireless_mode, set_wireless_mode
from core.utils.directory import get_config

import asyncio
import pywifi
import logging


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


async def get_wifi_ssid(interface):
    logging.basicConfig(level=logging.WARNING)
    wifi = pywifi.PyWiFi()

    int_face = None
    for i in wifi.interfaces():
        if i.name() == interface:
            int_face = i

    if int_face:
        int_face.scan()
        await asyncio.sleep(5)

        profiles = []
        for profile in int_face.scan_results():
            if profile.ssid.startswith("\x00\x00"):
                continue
            profiles.append({
                'ssid': profile.ssid,
                'bssid': profile.bssid
            })
        return profiles
    else:
        return None