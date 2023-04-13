#!/bin/pyhton3
# Modules:
import json
import datetime
import asyncio
from configparser import ConfigParser

# Functions:
from core.protocols.ble import bluetooth_enumeration
from core.vendors.hue import discover_philips_hue_bridge
from core.utils.nmap_scanner import nmap_enumeration, nmap_cpe_scan
from core.utils.formatting import create_scan_file_path
from core.modules.sniffing import capture_packets


class TextColor:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    GOLD = '\033[33m'
    BOLD = '\033[1m'
    END = '\033[0m'


# Main function for performing discovery/scanning/enumeration
def device_enumeration():
    config = ConfigParser()
    config.read("config.ini")

    path = create_scan_file_path()

    # Initial data for JSON scan file
    data = {
        "scan_start": str(datetime.datetime.now()),
        "scan_end": "",
        "hosts": {
            "ip_network": {},
            "ble": {},
            "zigbee": {}
        },
        "vulnerabilities": {}
    }

    # Discover and enumerate hosts on local IP network
    if config.getboolean("Scan Types", "ip_network"):
        discovered_ip_hosts = nmap_enumeration()
        data["hosts"]["ip_network"] = discovered_ip_hosts

        # CPE lookup for corresponding CVEs
        for host in discovered_ip_hosts:
            ports = nmap_cpe_scan(host)
            for port in ports:
                data["hosts"]["ip_network"][host]["ports"][port]["vulns"] = ports[port]

        # Discover Philips Hue bridge
        discovered_bridges = discover_philips_hue_bridge()
        for bridge in discovered_bridges:
            if bridge in data["hosts"]["ip_network"]:
                data["hosts"]["ip_network"][bridge]["bridge"] = vars(discovered_bridges[bridge])
            else:
                bridge_data = {"bridge": vars(discovered_bridges[bridge])}
                data["hosts"]["ip_network"][discovered_bridges[bridge]["ip"]] = bridge_data

    # Determine connectivity method (wired/Wi-Fi) for IP network devices through packet sniffing
    if config.getboolean("Scan Types", "wifi_sniffing"):
        capture_packets()

    # Discover and enumerate ble devices
    if config.getboolean("Scan Types", "ble"):
        bl_devices = asyncio.run(bluetooth_enumeration())
        print(f'Number of Bluetooth devices found: {TextColor.CYAN}{len(bl_devices)}{TextColor.END}')
        data["hosts"]["ble"] = bl_devices

    data["scan_end"] = str(datetime.datetime.now())

    # Create JSON file and insert data
    with open(path, "w") as file:
        json.dump(data, file, indent=4)
    print("Created scan file at '" + path + "'")
    print("Finished.")
