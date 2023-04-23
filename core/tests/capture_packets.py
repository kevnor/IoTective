from scapy.all import sniff, Packet
from scapy.layers.dot11 import Dot11


def packet_handler(pkt: Packet, hosts: list[str], bssid: str):
    print("----")
    print("Dest MAC: " + str(pkt.addr1))
    print("Client MAC: " + str(pkt.addr2))
    print("AP MAC: " + str(pkt.addr3))
    # Check if the packet contains the BSSID field
    if pkt.haslayer(Dot11):
        if pkt.addr2 == bssid:
            print("YEssss")


def get_hosts_on_bssid(bssid: str, interface: str) -> list[str]:
    hosts = []
    sniff(
        iface=interface,
        prn=lambda pkt: packet_handler(pkt=pkt, bssid=bssid, hosts=hosts),
        timeout=10,
        monitor=True
    )

    return hosts


print(get_hosts_on_bssid(interface="wlan0", bssid="00:31:92:AC:04:C2"))

