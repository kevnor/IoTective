from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11Elt
from scapy.all import *
from scapy.packet import Packet
from scapy.error import Scapy_Exception
import os
import subprocess
from rich.progress import Progress


async def wifi_sniffing(interface: str, logger, console) -> Dict[str, List]:
    # Get the name of the Wi-Fi network connected to the interface
    wifi_network = get_connected_wifi_network(interface=interface)
    hosts = {}

    if wifi_network is not None:
        set_monitor_mode = set_interface_mode(iface=interface, mode="Monitor", logger=logger)
        if not set_monitor_mode:
            return hosts

        bssids = discover_bssids_on_ssid(ssid=wifi_network['ESSID'], interface=interface, logger=logger)
        if len(bssids) > 0:
            hosts = discover_hosts_on_bssids(bssids=bssids, interface=interface, logger=logger)
        else:
            logger.warning(f"Did find any BSSID(s) of using '{wifi_network['ESSID']}' as SSID")
        set_interface_mode(iface=interface, mode="Managed", logger=logger)

    else:
        logger.error("Could not find Wi-Fi network")
    return hosts


def discover_hosts_on_bssids(bssids: Dict[str, List[str]], interface: str, logger) -> Dict[str, List[str]]:
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]  # 2.4 GHz channels
    #channels += [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157,
    #             161, 165]  # 5 GHz channels

    with Progress() as scanner:
        scan_task = scanner.add_task(f"[cyan]Host discovery on channel 1...",
                                     total=len(channels))
        for channel in channels:
            scanner.update(scan_task, description=f"[cyan]Host discovery on channel {channel}...")
            # Change the channel of the wireless interface
            os.system(f"iwconfig {interface} channel {channel}")

            # Define a packet handler function to extract MAC addresses
            def packet_handler(pkt: Packet):
                # Extract the source and destination MAC addresses from the packet
                if pkt.haslayer(Dot11) and pkt.type == 2:
                    # Extract the BSSID and source MAC address from the Data frame
                    bssid = pkt[Dot11].addr3
                    src_mac = pkt[Dot11].addr2
                    dst_mac = pkt[Dot11].addr1
                    print(pkt[Dot11].mysummary)
                    print(pkt[Dot11].address_meaning)
                    if bssid in bssids:
                        if src_mac == bssid and dst_mac not in bssids[bssid]:
                            bssids[bssid].append(dst_mac)
                        elif dst_mac == bssid and src_mac not in bssids[bssid]:
                            bssids[bssid].append(src_mac)

            # Sniff Wi-Fi packets for 10 seconds on the current channel
            try:
                sniff(prn=packet_handler, iface=interface, timeout=10)

            except Scapy_Exception as e:
                logger.error(e)
            scanner.update(scan_task, advance=1)
    return bssids


def discover_bssids_on_ssid(ssid: str, interface: str, logger) -> Dict[str, List[str]]:
    bssids = {}
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]  # 2.4 GHz channels
    channels += [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157,
                 161, 165]  # 5 GHz channels

    with Progress() as scanner:
        scan_task = scanner.add_task(f"[cyan]Discovering BSSIDs using '{ssid}' as SSID...",
                                     total=len(channels))
        for channel in channels:
            # Change the channel of the wireless interface
            os.system(f"iwconfig {interface} channel {channel}")

            # Define a packet handler function to extract MAC addresses
            def packet_handler(pkt: Packet):
                # Extract the source and destination MAC addresses from the packet
                if pkt.haslayer(Dot11) and pkt.haslayer(Dot11Elt) and pkt.info.decode() == ssid:
                    # Check if the packet is a Beacon frame or a Data frame
                    if pkt.type == 0 and pkt.subtype == 8:
                        # Extract the BSSID from the Beacon frame
                        bssid = pkt[Dot11].addr3
                        bssids.setdefault(bssid, [])

            scanner.update(scan_task, advance=1)

            # Sniff Wi-Fi packets for 2 seconds on the current channel
            try:
                sniff(prn=packet_handler, iface=interface, timeout=2)
            except Scapy_Exception as e:
                logger.error(e)
        return bssids


def set_interface_mode(iface: str, mode: str, logger) -> bool:
    # Check if interface exists
    if iface not in subprocess.check_output(["iwconfig"]).decode():
        logger.error(f"Interface {iface} does not exist")
        return False

    # Check if mode is valid
    if mode not in ["Managed", "Monitor"]:
        logger.error(f"Invalid mode {mode}")
        return False

    # Kill processes that may prevent monitor mode
    if mode == "monitor":
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)

    # Change mode
    subprocess.run(["ifconfig", iface, "down"], capture_output=True)
    subprocess.run(["iwconfig", iface, "mode", mode], capture_output=True)
    subprocess.run(["ifconfig", iface, "up"], capture_output=True)

    # Start network manager if we switched to managed mode
    if mode == "managed":
        subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)

    # Check if mode was set correctly
    output = subprocess.check_output(["iwconfig", iface]).decode()
    if mode in output:
        logger.info(f"Interface {iface} changed to mode {mode}")
        return True
    else:
        logger.error(f"Failed to change {iface} mode to {mode}")
        return False


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
