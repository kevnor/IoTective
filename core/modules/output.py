from prettytable import PrettyTable
from core.utils.directory import get_latest_scan_path
import json
from configparser import ConfigParser
from rich.console import Console
from rich.table import Table
from rich.text import Text


def display_bluetooth_devices():
    path = get_latest_scan_path()

    if not path:
        return

    with open(path, "r") as file:
        json_file = json.loads(file.read())
        bt_devices = json_file["hosts"]["ble"]

    table = PrettyTable()
    table.field_names = ["RSSI", "Address", "Name", "Services"]

    for device in bt_devices:
        dev = bt_devices[device]

        table.add_row([
            dev['rssi'],
            dev['address'],
            dev['name'],
            len(dev['services'])
        ])

    print(table)


def print_scan_type_config():
    config = ConfigParser()
    config.read("config.ini")

    table = Table(title="Scan Type Configuration")
    table.add_column("Scan Type", style="cyan")
    table.add_column("Enabled", justify="right")

    # Modify the code below to format the boolean values as "yes" or "no"
    for scan_type, enabled in config.items("Scan Types"):
        enabled_text = Text()
        if config.getboolean("Scan Types", scan_type):
            enabled_text.append("Yes", style="green")
        else:
            enabled_text.append("No", style="red")

        table.add_row(scan_type, enabled_text)

    console = Console()
    console.print(table)


def print_nics(nics):
    console = Console()
    table = Table(title="Available Network Interfaces")
    table.add_column("Nr", style="cyan")
    table.add_column("Name")
    table.add_column("IPv4 Address")
    table.add_column("Netmask")

    for nic in nics:
        table.add_row(
            str(nic),
            nics[nic]["name"],
            nics[nic]["IPv4"]['address'] if "IPv4" in nics[nic] else "",
            nics[nic]["IPv4"]['netmask'] if "IPv4" in nics[nic] else ""
        )

    console.print(table)


def print_nic_config():
    config = ConfigParser()
    config.read("config.ini")

    table = Table(title="Network Interface Configuration")
    table.add_column("Attribute", style="cyan")
    table.add_column("Value")

    for attribute, value in config.items("Network Interface"):
        table.add_row(attribute, value)

    console = Console()
    console.print(table)


def print_wireless_interfaces(interfaces):
    if len(interfaces) < 1:
        print_error("No suitable adapters found")
        return False
    else:
        table = Table(title="Available Wireless Adapters")
        table.add_column("Nr", style="cyan")
        table.add_column("PHY")
        table.add_column("Interface")
        table.add_column("Driver")
        table.add_column("Chipset")

        count = 0
        for interface in interfaces:
            count += 1
            table.add_row(
                str(count),
                interface["phy"],
                interface["interface"],
                interface["driver"],
                interface["chipset"]
            )
        console = Console()
        console.print(table)
        return True


def print_wireless_networks(profiles):
    if len(profiles) < 1:
        print_error("No networks found")
        return False
    else:
        table = Table(title="Available Wireless Networks")
        table.add_column("Nr", style="cyan")
        table.add_column("SSID")
        table.add_column("BSSID")

        count = 0
        for profile in profiles:
            if profile['ssid'].startswith("\x00\x00"):
                continue
            count += 1
            table.add_row(
                str(count),
                str(profile['ssid']),
                str(profile['bssid']),
            )
        console = Console()
        console.clear()
        console.print(table)


def print_error(message):
    console = Console()
    text = Text()
    text.append("ERROR: ", style="bold red")
    text.append(message)
    console.print(text)
