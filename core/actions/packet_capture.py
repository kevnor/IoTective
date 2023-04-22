from scapy.layers.dot11 import Dot11
from scapy.sendrecv import wrpcap
from core.utils.host import get_wireless_mode, set_wireless_mode
from core.utils.directory import get_config
import asyncio
import pywifi
import logging
from scapy.all import sniff, Packet

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


def packet_callback(pkt: Packet, bssids: list, essid_to_find: str, logger):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            # This is a Beacon frame
            bssid = pkt.addr3
            essid = pkt.info.decode('utf-8')
            if essid == essid_to_find and bssid not in bssids:
                bssids.append(bssid)
                logger.info(f"Discovered BSSID: '{bssid}'")


def get_bssid_for_essid(essid: str, logger, interface: str) -> list[str]:
    bssids = []
    logger.info(f"Discovering BSSID for APs using ESSID: '{essid}'")
    logger.info("Searching for 20 seconds...")
    sniff(
        iface=interface,
        monitor=True,
        prn=lambda pkt: packet_callback(pkt=pkt, bssids=bssids, essid_to_find=essid, logger=logger),
        timeout=20
    )
    return bssids
