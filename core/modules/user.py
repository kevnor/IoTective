from core.utils.host import get_nics, get_usb_devices
from prettytable import PrettyTable
from core.utils.console import print_nics, print_wireless_networks
from rich.console import Console
from rich.prompt import Prompt

import json


def choose_zigbee_device():
    usb_devices = get_usb_devices()
    table = PrettyTable()
    table.field_names = ["", "Device", "Tag", "ID"]

    if not usb_devices:
        print("Could not find any USB devices.")
        return

    count = -1
    for device in usb_devices:
        count += 1
        table.add_row([count, device['device'], device['tag'], device['id']])
    table.align = "l"
    print(table)

    while True:
        chosen_device = int(input('Choose device: '))
        if chosen_device:
            return usb_devices[chosen_device]
        print("Invalid input.")


def choose_nic():
    nics = get_nics()

    if not nics:
        print("Could not find any network interfaces.")
        return

    print_nics(nics)
    nic_nrs = [str(nic) for nic in nics]
    chosen_nic = Prompt.ask("Choose a network interface for IP scanning: ", choices=nic_nrs)
    return nics[int(chosen_nic)]


def choose_targets():
    import os
    table = PrettyTable()
    table.field_names = ["", "IPv4", "MAC", "Vendor", "Open ports", "OS (predicted)"]
    addresses = []

    path = os.getcwd().split("/")
    path.append("scans")
    path.append("scan.json")
    path = "/".join(path)

    # Write IPv4 and MAC to JSON file
    with open(path, 'r') as file:
        data = json.load(file)
        hosts = data["hosts"]

    # Create table of hosts to display in command prompt:
    for host in hosts:
        print(host)
        ip = host
        mac = ""
        vendor = ""
        open_ports = ""
        os = ""
        if host["mac"]:
            mac = host["mac"]
        if host["ports"]:
            ports = []
            for port in hosts[host]["ports"]:
                ports.append(port)
            open_ports = str(ports)
        if hosts[host]["vendor"]:
            vendor = hosts[host]["vendor"]
        if hosts[host]['os']:
            os = "(" + hosts[host]['os'][0]['accuracy'] + "%) - " + hosts[host]['os'][0]['name']
        table.add_row([len(addresses), ip, mac, vendor, open_ports, os])
        addresses.append(host)
    table.align = "l"
    print(table)

    # User chooses what hosts to target from the table:
    while True:
        chosen_targets = str(input('Choose targets (separate targets with ","): '))
        chosen_targets.replace(" ", "")
        chosen_targets.split(",")
        chosen_targets = [s for s in chosen_targets if s.isdigit()]
        new_hosts = {}
        if chosen_targets:
            for target in chosen_targets:
                new_hosts[addresses[int(target)]] = hosts.get(addresses[int(target)])
            break
        print("Invalid input.")
    return new_hosts


def choose_ssid(profiles):
    console = Console()
    console.clear()
    print_wireless_networks(profiles)
    options = [str(i+1) for i in range(len(profiles))]

    chosen_network = Prompt.ask("Choose a network to perform sniffing on", choices=options, show_choices=False)
    console.clear()

    return profiles[int(chosen_network) - 1]["ssid"]
