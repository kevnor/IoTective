from core.utils.directory import get_config
import json
import datetime
import asyncio
from rich.console import Console

# Functions:
from core.actions.ble_enumeration import bluetooth_enumeration
from core.actions.packet_capture import wifi_sniffing
from core.utils.directory import create_scan_file


async def main():
    config, config_file = get_config()
    console = Console()
    console.clear()
    data, path = create_scan_file()
    console.log(f"Created scan file at '" + path + "'")

    console.status("Working...")
    # Enumerate devices on the network using nmap
    # Determine connectivity method (wired/Wi-Fi) for IP network devices through packet sniffing
    if config.getboolean("Scan Types", "wifi_sniffing"):
        console.log("Initializing Wi-Fi sniffing...")
        wifi_sniffing()
        console.log("Finished Wi-Fi sniffing")

    # Discover and enumerate ble devices
    if config.getboolean("Scan Types", "ble"):
        console.log("Initializing Bluetooth LE enumeration...")
        data["hosts"]["ble"] = asyncio.gather(bluetooth_enumeration())
        console.log(f"Discovered [cyan]{len(data['hosts']['ble'])}[/cyan] Bluetooth LE devices")

    data["scan_end"] = str(datetime.datetime.now())
    console.log(f"Scan finished at {data['scan_end']}")

    # Create JSON file and insert data
    with open(path, "w") as file:
        json.dump(data, file, indent=4)



