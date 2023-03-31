#!/bin/pyhton3
# Modules:
import json
import os
import time
import datetime
import asyncio
from configparser import ConfigParser
from nmap import PortScanner

# Functions:
from core.protocols.bluetooth import bluetooth_enumeration
from core.vendors.hue import discover_philips_hue_bridge
from core.utils.formating import subnet_to_cidr


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

    # Create path and name for JSON file
    slash = os.path.sep
    timestr = time.strftime("%Y%m%d-%H%M%S")
    path = os.getcwd().split(slash)
    path.append("scans")
    path.append("scan_" + timestr + ".json")
    path = slash.join(path)

    # Initial data for JSON scan file
    data = {
        "scan_start": str(datetime.datetime.now()),
        "scan_end": "",
        "hosts": {
            "ip_network": {},
            "bluetooth": {},
            "zigbee": {}
        },
        "vulnerabilities": {}
    }

    # Discover and enumerate hosts on local IP network
    if config.getboolean("Scan Types", "ip_network"):
        discovered_ip_hosts = nmap_enumeration()
        data["hosts"]["ip_network"] = discovered_ip_hosts

        # Discover Philips Hue bridge
        discovered_bridges = discover_philips_hue_bridge()
        for bridge in discovered_bridges:
            if bridge in data["hosts"]["ip_network"]:
                data["hosts"]["ip_network"][bridge]["bridge"] = vars(discovered_bridges[bridge])
            else:
                bridge_data = {"bridge": vars(discovered_bridges[bridge])}
                data["hosts"]["ip_network"][discovered_bridges[bridge]["ip"]] = bridge_data

    # Discover and enumerate bluetooth devices
    if config.getboolean("Scan Types", "bluetooth"):
        bl_devices = asyncio.run(bluetooth_enumeration())
        print(f'Number of Bluetooth devices found: {TextColor.CYAN}{len(bl_devices)}{TextColor.END}')
        data["hosts"]["bluetooth"] = bl_devices

    data["scan_end"] = str(datetime.datetime.now())

    # Create JSON file and insert data
    with open(path, "w") as file:
        json.dump(data, file, indent=4)
    print("Created scan file at '" + path + "'")
    print("Finished.")


# Nmap is used to discover open ports and detect OS
def nmap_enumeration():
    nm = PortScanner()

    # Get network interface configuration
    config = ConfigParser()
    config.read("config.ini")
    nic = config["Network Interface"]
    ip_range = f"{nic['ipv4']}/{subnet_to_cidr(nic['netmask'])}"

    # Perform nmap scan on IP range of network interface
    print(f"Performing host discovery and port scanning on IP range {ip_range}...")
    """nmap arguments:"""
    """(-n) disable reverse DNS resolution"""
    """(-p) specify ports"""
    """(-PE) ICMP echo ping"""
    """(-PS) TCP SYN ping"""
    """(-PU) UDP ping"""
    """(-PA) TCP ACK ping"""
    """(-T) Timing templates (0-5)"""
    """(--source-port) manually specify a source port"""

    arguments = "-n -sV -PE -PS80,3389,443 -PU40125,161 -PA21 --source-port 53 -T4 --open " + ip_range
    scan_results = nm.scan(arguments=arguments)
    print(f'Number of devices found: {TextColor.CYAN}{len(scan_results["scan"])}{TextColor.END}')
    output = {}

    # Extract useful information from the scan
    for host in scan_results["scan"]:
        print(str(json.dumps(scan_results["scan"][host], indent=4)))
        if host in ["127.0.0.1"] or "mac" not in scan_results["scan"][host]["addresses"]:
            continue
        output[host] = {
            "addresses": scan_results["scan"][host]["addresses"],
            "vendor": {},
            "ports": {},
            "os": {}
        }
        if "vendor" in scan_results["scan"][host] and scan_results["scan"][host]["vendor"]:
            output[host]["vendor"] = scan_results["scan"][host]["vendor"][output[host]["addresses"]["mac"]]
        if "tcp" in scan_results["scan"][host] and scan_results["scan"][host]["tcp"]:
            output[host]["ports"] = scan_results["scan"][host]["tcp"]
        if "osmatch" in scan_results["scan"][host] and scan_results["scan"][host]["osmatch"]:
            output[host]["os"] = scan_results["scan"][host]["osmatch"]
    return output
