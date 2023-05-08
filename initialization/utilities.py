import socket
import psutil
import netifaces
import subprocess
from reporting.console import choose_nic
import ipaddress
from pyroute2 import IW
from pyroute2 import IPRoute
from pyroute2.netlink import NetlinkError
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from configparser import ConfigParser


def get_ip_ranges() -> list:
    int_faces = []

    for int_face, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            try:
                ip_address = ipaddress.IPv4Address(addr.address)
            except ValueError:
                continue

            if ip_address.is_loopback or ip_address.is_unspecified:
                continue

            int_faces.append({
                'interface': str(int_face),
                'ip_address': str(ip_address),
                'netmask': str(addr.netmask),
            })
    return int_faces


def get_ip_range(logger, console) -> str:
    int_faces = {}

    for int_face, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            try:
                ip_address = ipaddress.IPv4Address(addr.address)
            except ValueError:
                continue

            if ip_address.is_loopback or ip_address.is_unspecified:
                continue

            int_faces[int_face] = {
                'ip_address': str(ip_address),
                'netmask': str(addr.netmask),
            }

    if len(int_faces) > 1:
        logger.info(f"Found multiple private network interfaces")
        nic = choose_nic(console=console, interfaces=int_faces)
        ip_range = int_faces[nic]["ip_address"] + "/" + subnet_to_cidr(int_faces[nic]["netmask"])
        return ip_range
    elif len(int_faces) == 1:
        for int_face in int_faces:
            ip_range = int_faces[int_face]["ip_address"] + "/" + subnet_to_cidr(int_faces[int_face]["netmask"])
            return ip_range
    else:
        return ""


def get_interface_for_ip_range(ip_range: str) -> str:
    subnet_mask = None
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if socket.AF_INET in addrs:
            for addr in addrs[socket.AF_INET]:
                if 'netmask' in addr and 'addr' in addr:
                    subnet_mask = addr.get('netmask')
                    break
            if subnet_mask:
                break
    if subnet_mask:
        subnet_cidr = subnet_to_cidr(subnet_mask)
        network_address = ipaddress.IPv4Network(ip_range, False).supernet(new_prefix=int(subnet_cidr))
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if socket.AF_INET in addrs:
                for addr in addrs[socket.AF_INET]:
                    if 'addr' in addr and ipaddress.IPv4Address(addr.get('addr')) in network_address:
                        return interface
    return ""


def is_wireless_interface(iface: str) -> bool:
    ip = IPRoute()
    iw = IW()
    index = ip.link_lookup(ifname=iface)[0]
    try:
        iw.get_interface_by_ifindex(index)
        iw.close()
        ip.close()
        return True
    except NetlinkError as e:
        if e.code == 19:  # 19 'No such device'
            iw.close()
            ip.close()
            return False


def check_monitor_mode_support(interface: str) -> bool:
    try:
        # Check if the interface supports monitoring mode
        output = subprocess.check_output(f"iw list | grep -A4 {interface} | grep -o 'Monitor'", shell=True)
        if "Monitor" in output.decode():
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        # Interface not found
        return False


def subnet_to_cidr(subnet_mask: str) -> str:
    """
    Converts a subnet mask to CIDR notation.

    Args:
    subnet_mask (str): Subnet mask in dotted decimal notation (e.g. "255.255.255.0")

    Returns:
    int: CIDR notation (e.g. 24 for subnet mask "255.255.255.0")
    """
    # Validate the input
    parts = subnet_mask.split('.')
    if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        raise ValueError("Invalid subnet mask")

    # Convert subnet mask to binary string
    binary_mask = ''.join([bin(int(x))[2:].zfill(8) for x in subnet_mask.split('.')])

    # Count the number of consecutive ones in the binary string
    cidr = 0
    for i in range(len(binary_mask)):
        if binary_mask[i] == '1':
            cidr += 1
        else:
            break

    return str(cidr)


def choose_zigbee_device(logger, console: Console) -> str:
    devices = os.listdir("/dev/serial/by-id/")
    logger.info(f"Found {len(devices)} serial device(s) connected to the host")

    if len(devices) == 1:
        use_device = Confirm.ask(f"Use '{devices[0]}' for ZigBee sniffing?")
        if use_device:
            return f"/dev/serial/by-id/{devices[0]}"
    elif len(devices) > 1:
        panel = Panel("\n".join([f"{i}. {device}" for i, device in enumerate(devices, start=1)]),
                      title="Select a device from the list")
        console.print(panel)
        selected_item = Prompt.ask("Enter the number of the item you want to select",
                                   choices=[str(i) for i in range(1, len(devices) + 1)])
        return f"/dev/serial/by-id/{devices[int(selected_item) - 1]}"
    else:
        logger.error("Could not find any serial devices connected to the host")
    return ""

def write_configuration(configuration: dict) -> None:
    config = ConfigParser()

