from core.utils.directory import get_config
from core.utils.formatting import create_scan_file_path, subnet_to_cidr
from core.modules.ip_scanning import ip_scanning
import json
import datetime
import asyncio
from rich.console import Console

# Functions:
from core.protocols.ble import bluetooth_enumeration
from core.modules.sniffing import wifi_sniffing


def main():
    config, config_file = get_config()
    path = create_scan_file_path()
    console = Console()
    console.clear()

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
    with console.status("Working..."):
        # Enumerate devices on the network using nmap
        if config.getboolean("Scan Types", "ip_network"):
            ip = config.get("Network Interface", "ipv4")
            netmask = config.get("Network Interface", "netmask")
            ip_range = f"{ip}/{subnet_to_cidr(netmask)}"

            console.log("Initializing IP scanning...")
            console.log(f"Performing host discovery and port scanning on IP range {ip_range}...")
            data["hosts"]["ip_network"] = ip_scanning()
            console.log(f"Discovered [cyan]{len(data['hosts']['ip_network'])}[/cyan] hosts using nmap")

        # Determine connectivity method (wired/Wi-Fi) for IP network devices through packet sniffing
        if config.getboolean("Scan Types", "wifi_sniffing"):
            console.log("Initializing Wi-Fi sniffing...")
            wifi_sniffing()
            console.log("Finished Wi-Fi sniffing")

        # Discover and enumerate ble devices
        if config.getboolean("Scan Types", "ble"):
            console.log("Initializing Bluetooth LE enumeration...")
            data["hosts"]["ble"] = asyncio.run(bluetooth_enumeration())
            console.log(f"Discovered [cyan]{len(data['hosts']['ble'])}[/cyan] Bluetooth LE devices")

        data["scan_end"] = str(datetime.datetime.now())
        console.log(f"Scan finished at {data['scan_end']}")

        # Create JSON file and insert data
        with open(path, "w") as file:
            json.dump(data, file, indent=4)
        console.log(f"Created scan file at '" + path + "'")
