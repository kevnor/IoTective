from prettytable import PrettyTable
from rich.align import Align

from core.utils.directory import get_latest_scan_path
import json
from configparser import ConfigParser
from rich.text import Text
import logging
from argparse import ArgumentParser
from platform import system
from os import get_terminal_size
import textwrap
from rich.console import Console, Group
from rich.layout import Layout
from rich.table import Table
from rich.panel import Panel
from datetime import datetime
from rich import box

from core.utils.models import Host, Port


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


def banner(msg, color, console) -> None:
    term_width = get_terminal_width()

    console.rule(style=color)
    wrapped_msg = "\n".join(textwrap.wrap(msg, width=term_width))
    console.print(wrapped_msg, justify="center", style=color)
    console.rule(style=color)


def get_terminal_width() -> int:
    try:
        width, _ = get_terminal_size()
    except OSError:
        width = 80

    if system().lower() == "windows":
        width -= 1

    return width


def print_scan_type_config():
    config = ConfigParser()
    config.read("config.ini")

    # Use dictionary comprehension to format boolean values
    scan_types = {scan_type: "Yes" if config.getboolean("Scan Types", scan_type) else "No"
                  for scan_type in config.options("Scan Types")}

    table = Table(title="Scan Type Configuration")
    table.add_column("Scan Type", style="cyan")
    table.add_column("Enabled", justify="right")

    # Add rows to table
    for scan_type, enabled in scan_types.items():
        table.add_row(scan_type, enabled)

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
        ipv4_address = f"{nics[nic]['IPv4']['address']}" if "IPv4" in nics[nic] else ""
        ipv4_netmask = f"{nics[nic]['IPv4']['netmask']}" if "IPv4" in nics[nic] else ""
        table.add_row(
            str(nic),
            nics[nic]["name"],
            ipv4_address,
            ipv4_netmask
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
    if not interfaces:
        print_error("No suitable adapters found")
        return False

    table = Table(title="Available Wireless Adapters")
    table.add_column("Nr", style="cyan")
    table.add_column("PHY")
    table.add_column("Interface")
    table.add_column("Driver")
    table.add_column("Chipset")

    for count, interface in enumerate(interfaces, start=1):
        table.add_row(
            str(count),
            interface.get("phy", ""),
            interface.get("interface", ""),
            interface.get("driver", ""),
            interface.get("chipset", "")
        )
    console = Console()
    console.print(table)
    return True


def print_wireless_networks(profiles):
    try:
        if not profiles:
            raise ValueError("No networks found")

        table = Table(title="Available Wireless Networks")
        table.add_column("Nr", style="cyan")
        table.add_column("SSID")
        table.add_column("BSSID")

        for count, profile in enumerate(profiles, start=1):
            if profile['ssid'].startswith("\x00\x00"):
                continue
            table.add_row(
                f"{count}",
                f"{profile['ssid']}",
                f"{profile['bssid']}",
            )

        console = Console()
        console.clear()
        console.print(table)

    except Exception as e:
        logging.error(f"Error occurred while printing wireless networks: {e}")
        return False
    else:
        return True


def print_error(message):
    console = Console()
    text = Text()
    text.append("ERROR: ", style="bold red")
    text.append(message)
    console.print(text)


def cli():
    parser = ArgumentParser(
        prog="IoTective",
        description="Internet of Things automated security scanning and penetration testing tool."
    )

    parser.add_argument(
        "-c",
        "--configure",
        help="start configuration wizard",
        required=False,
        action="store_true"
    )

    parser.add_argument(
        "--run",
        required=False,
        action="store_true",
        help="run the scanner"
    )

    parser.add_argument(
        "-st",
        "--scan-type",
        help="Scan type.",
        type=str,
        required=False,
        default=None,
        choices=["arp", "ping"],
    )

    parser.add_argument(
        "-m",
        "--mode",
        help="Scan mode.",
        default="normal",
        type=str,
        required=False,
        choices=["evade", "noise", "normal"],
    )

    return parser.parse_args()


def make_host_scan_layout(port_size: int) -> Layout:
    """Define the layout."""
    layout = Layout(name="host")

    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", minimum_size=port_size),
    )
    layout["main"].split_row(
        Layout(name="info"),
        Layout(name="ports"),
    )
    return layout


def make_header(host_ip) -> Panel:
    grid = Table.grid(expand=True)
    grid.add_column(justify="center")
    grid.add_column(justify="right")
    grid.add_row(
        f"[b]Host[/b] {host_ip}",
        datetime.now().ctime().replace(":", "[blink]:[/]"),
    )
    return Panel(grid, style="red")


def make_host_info(host: Host) -> Panel:
    host_info = Table.grid(padding=1)
    host_info.add_column(style="green", justify="right")
    host_info.add_column(no_wrap=True)

    host_info.add_row("MAC Address", host.mac)
    host_info.add_row("Vendor", host.vendor)
    host_info.add_row("OS", host.os)
    host_info.add_row("Accuracy", str(host.os_accuracy))
    host_info.add_row("Type", host.os_type[:20])

    info_panel = Panel(
        Align.center(
            Group(Align.center(host_info)),
            vertical="middle"
        ),
        box=box.ROUNDED,
        padding=(1, 2),
        title="[b red]Host Information",
        border_style="red"
    )

    return info_panel


def make_port_info(ports: list[Port]) -> Panel:
    print(len(ports))
    if len(ports) > 0:
        port_info = Table(padding=1, box=box.MINIMAL)
        port_info.add_column("Port", style="cyan")
        port_info.add_column("Service", style="blue")
        port_info.add_column("Product", style="red")
        port_info.add_column("Version", style="yellow")
        port_info.add_column("CVEs", style="red")

        for port in ports:
            port_info.add_row(
                port.port_id,
                port.service_name,
                port.product,
                port.version,
                str(len(port.cves)))
    else:
        port_info = Text("No open ports identified.")

    port_panel = Panel(
        Align.center(
            Group(Align.center(port_info)),
            vertical="middle"
        ),
        box=box.ROUNDED,
        padding=(1, 2),
        title="[b red]Port Information",
        border_style="red"
    )

    return port_panel
