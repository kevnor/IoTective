from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, Dot11ProbeResp
from scapy.all import *
import os
from collections import OrderedDict
import subprocess


async def wifi_sniffing(interface: str, logger, console) -> Dict[str, List]:
    # Get the name of the Wi-Fi network connected to the interface
    wifi_network = get_connected_wifi_network(interface=interface)

    if wifi_network is not None:



        # Retrieve BSSIDs that use the ESSID of the AP
        ap_bssids = discover_bssids_for_ssid(interface=interface, ssid=wifi_network['ESSID'], logger=logger)
        hosts = {}

        # Get MAC addresses of hosts connected to each BSSID
        if len(ap_bssids) > 0:
            for bid in ap_bssids:
                hosts[bid] = []
                for channel in ap_bssids[bid]:
                    hosts[bid].append(get_unique_hosts(interface=interface, bssid=bid, channel=channel, logger=logger))
        else:
            logger.error("Did not manage to capture BSSID(s) of AP")

        # clean_up_interface = set_wireless_mode(interface=interface, new_mode="Managed")
        return hosts
    else:
        logger.error("Could not switch to monitoring mode")


def get_connected_wifi_network(interface: str) -> dict:
    try:
        output = subprocess.check_output(['iwconfig', interface])
        output = output.decode('utf-8')
        result = {
                "ESSID": "",
                "BSSID": ""
                  }
        for line in output.split('\n'):
            if "ESSID:" in line:
                result["ESSID"] = line.split('"')[1]
            if "Access Point:" in line:
                result["BSSID"] = line.split("Access Point:")[1]
        return result
    except subprocess.CalledProcessError:
        pass
    return {}


def get_hosts_on_bssid(bssid: str, logger, interface: str) -> list[str]:
    hosts = []

    def packet_handler(pkt: Packet):
        # Check if the packet contains a Wi-Fi layer
        if pkt.haslayer(Dot11):
            # Check if the packet is a data packet and contains the BSSID field
            if pkt.type == 2 and pkt.addr3:
                # Get the BSSID of the access point
                bssid = pkt.addr3
                # Get the source MAC address of the data packet
                src = pkt.addr2
                # Display the information
                hosts.append(pkt.addr2)
                print(f"Host {src} is connected to {bssid}")

    sniff(
        iface=interface,
        prn=packet_handler,
        lfilter=lambda pkt: pkt.haslayer(Dot11) and pkt.addr3 == bssid
    )

    return hosts


def get_unique_hosts(interface: str, channel: int, bssid: str, logger) -> list:
    # Change the channel of the wireless interface
    os.system(f"iwconfig {interface} channel {channel}")

    # Initialize a set to store the unique hosts
    unique_hosts = OrderedDict()

    # Define a packet handler function to extract MAC addresses
    def packet_handler(pkt):
        # Extract the source and destination MAC addresses from the packet
        src_mac = pkt.addr2
        dst_mac = pkt.addr1

        # Check if the source or destination MAC address matches the BSSID
        if src_mac == bssid or dst_mac == bssid:
            # Add the MAC address to the dictionary if it hasn't been seen before
            if src_mac not in unique_hosts:
                unique_hosts[src_mac] = True
            if dst_mac not in unique_hosts:
                unique_hosts[dst_mac] = True

    logger.info(f"Discovering hosts on channel {channel}")
    # Sniff Wi-Fi packets for 10 seconds on the current channel
    sniff(prn=packet_handler, iface=interface, timeout=10)

    # Convert the set to a list and return it
    return list(unique_hosts)


def discover_bssids_for_ssid(interface: str, ssid: str, logger) -> dict:
    # Initialize an empty dictionary to store the discovered BSSIDs and channels
    bssid_dict = {}

    # Function to process Wi-Fi packets and extract BSSIDs
    def packet_handler(pkt, chnl: int):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            # Extract the SSID from the packet
            ssid_from_packet = pkt[Dot11Elt].info.decode()
            # Check if the SSID matches the one we're looking for
            if ssid_from_packet == ssid:
                # Extract the BSSID from the packet
                bssid = pkt[Dot11].addr2
                # Add the BSSID and channel to the dictionary
                if bssid not in bssid_dict:
                    bssid_dict[bssid] = [chnl]
                    logger.info(f"Found BSSID: {bssid} on channel {chnl}")
                else:
                    if chnl not in bssid_dict[bssid]:
                        bssid_dict[bssid].append(chnl)
                        logger.info(f"Found BSSID: {bssid} on channel {chnl}")

    # Loop through every Wi-Fi channel in both the 2.4GHz and 5GHz bands
    logger.info("Searching on 2.4GHz bands...")
    for channel in range(1, 14):
        logger.info(f"Searching on channel {channel}...")
        # Set the Wi-Fi interface to the current channel
        os.system(f"iwconfig {interface} channel {channel}")
        # Sniff Wi-Fi packets for 2 seconds on the current channel
        sniff(prn=lambda pkt: packet_handler(pkt=pkt, chnl=channel), iface=interface, timeout=2)

    logger.info("Searching on 5GHz bands...")
    channel = 36
    while 36 <= channel <= 165:
        previous_dict = bssid_dict.copy()
        logger.info(f"Searching on channel {channel}...")
        # Set the Wi-Fi interface to the current channel
        os.system(f"iwconfig {interface} channel {channel}")
        # Sniff Wi-Fi packets for 2 seconds on the current channel
        sniff(prn=lambda pkt: packet_handler(pkt=pkt, chnl=channel), iface=interface, timeout=2)

        if bssid_dict != previous_dict:
            channel += 1
        else:
            channel += 4

    # Return the list of discovered BSSIDs
    return bssid_dict
