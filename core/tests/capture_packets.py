from scapy.all import *
from scapy.layers.dot11 import Dot11


def packet_callback(pkt: Packet, bssids: list, essid_to_find: str):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            # This is a Beacon frame
            bssid = pkt.addr3
            essid = pkt.info.decode('utf-8')
            if essid == essid_to_find and bssid not in bssids:
                bssids.append(bssid)


def get_bssid_for_essid(essid: str) -> list[str]:
    bssids = []
    sniff(
        iface="wlan0",
        monitor=True,
        prn=lambda pkt: packet_callback(pkt=pkt, bssids=bssids, essid_to_find=essid),
        timeout=20
    )
    return bssids


print(get_bssid_for_essid(essid="Girls Gone Wireless"))

