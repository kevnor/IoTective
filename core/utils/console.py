from prettytable import PrettyTable
from rich.align import Align

from core.utils.directory import get_latest_scan_path
import json
from rich.text import Text
import logging
from platform import system
from os import get_terminal_size
import textwrap
from rich.console import Console, Group
from rich.prompt import Prompt
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


def print_arp_scan_hosts(hosts: list[Host], console):
    table = Table()
    table.add_column("MAC")
    table.add_column("IPv4")
    table.add_column("Vendor")

    for host in hosts:
        table.add_row(host.mac, host.ip, host.vendor)

    console.print(table)


def make_host_scan_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="host")

    layout.split(
        Layout(name="header", size=3),
        Layout(name="main"),
    )
    layout["main"].split_row(
        Layout(name="info"),
        Layout(name="ports"),
    )
    return layout


def choose_nic(console, interfaces: dict) -> str:
    # create table headers
    table = Table(title="Network Interfaces")
    table.add_column(justify="right", style="red")
    table.add_column("Name", justify="left", style="cyan")
    table.add_column("IP Range", justify="left", style="magenta")
    count = 0

    lookup = {}

    # get all network interfaces and their IP addresses
    for interface in interfaces:
        count += 1
        ip_address = interfaces[interface]["ip_address"]
        netmask = interfaces[interface]["netmask"]
        lookup[count] = interface

        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        table.add_row(str(count), interface, f"{ip_address}/{cidr}")

    # display table and prompt user to choose an interface
    console.print(table)
    selected_interface = None
    while selected_interface is None:
        selected_row = Prompt.ask("Select an interface: ", choices=[str(i+1) for i in range(len(interfaces))])
        selected_interface = lookup[int(selected_row)] if lookup[int(selected_row)] else None

    return selected_interface


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
    if ports is not None and len(ports) > 0:
        port_info = Table(padding=1, box=box.MINIMAL)
        port_info.add_column("Port", style="cyan")
        port_info.add_column("Service", style="blue")
        port_info.add_column("Product", style="red")
        port_info.add_column("Version", style="yellow")
        port_info.add_column("CVEs", style="red")

        for port in ports:
            cve_nr = 0
            if port.cves is not None:
                cve_nr = len(port.cves)

            port_info.add_row(
                port.port_id,
                port.service_name,
                port.product,
                port.version,
                str(cve_nr)
            )
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
