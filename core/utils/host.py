from __future__ import print_function

import ctypes
import socket
import psutil
import netifaces
import os
import subprocess
from core.utils.console import print_error, choose_nic
from core.utils.formatting import subnet_to_cidr
import sys
import ipaddress
from pyroute2 import IW
from pyroute2 import IPRoute
from pyroute2.netlink import NetlinkError


def get_default_gateway():
    gws = netifaces.gateways()
    gateway = gws['default'][netifaces.AF_INET][0]
    return gateway


def get_usb_devices():
    import re
    import subprocess
    device_re = re.compile(b"Bus\s+(?P<bus>\d+)\s+Device\s+(?P<device>\d+).+ID\s(?P<id>\w+:\w+)\s(?P<tag>.+)$", re.I)
    df = subprocess.check_output("lsusb")
    devices = []
    for line in df.split(b'\n'):
        if line:
            info = device_re.match(line)
            if info:
                dinfo = info.groupdict()
                dinfo['bus'] = dinfo['bus'].decode("utf-8")
                dinfo['id'] = dinfo['id'].decode("utf-8")
                dinfo['tag'] = dinfo['tag'].decode("utf-8")
                dinfo['device'] = '/dev/bus/usb/%s/%s' % (dinfo.pop('bus'), dinfo.pop('device').decode("utf-8"))
                devices.append(dinfo)
    return devices


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


def get_connected_wifi_network(interface: str) -> dict | None:
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
    return None


def get_wireless_mode(interface: str):
    # Run the iwconfig command and capture the output
    completed_process = subprocess.run(['iwconfig', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Check if there was an error running the command
    if completed_process.returncode != 0:
        print(f"Error running iwconfig {interface}: {completed_process.stderr.decode().strip()}")
        return None

    # Convert the output to a string and split it into lines
    output = completed_process.stdout.decode('utf-8')
    lines = output.split('\n')

    # Search for the wireless mode in the output
    for line in lines:
        if 'Mode:' in line:
            mode = line.split('Mode:')[1].split()[0]
            return mode
    else:
        print("Wireless mode not found")
        return None


def set_wireless_mode(interface: str, new_mode: str = "Monitor") -> bool:
    current_mode = get_wireless_mode(interface)

    if current_mode == new_mode:
        return True
    else:
        try:
            if new_mode == "Monitor":
                check = subprocess.check_call(["sudo airmon-ng check kill"], shell=True)
                start = subprocess.check_call(["sudo airmon-ng start " + interface], shell=True)
            else:
                stop = subprocess.check_call(["sudo airmon-ng stop " + interface], shell=True)
                start_network = subprocess.check_call(["sudo systemctl start NetworkManager"], shell=True)
            return True
        except subprocess.CalledProcessError as e:
            print_error(e)
            return False


def is_root() -> bool:
    if os.name == 'posix':
        return os.getuid() == 0
    elif os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        except:
            return False
    else:
        print("Unknown OS, unable to determine root status")
        sys.exit(1)


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
        ip_range = int_faces[nic]["ip_address"] + "/" + str(subnet_to_cidr(int_faces[nic]["netmask"]))
        return ip_range
    elif len(int_faces) == 1:
        for int_face in int_faces:
            ip_range = int_faces[int_face]["ip_address"] + "/" + str(subnet_to_cidr(int_faces[int_face]["netmask"]))
            return ip_range
    else:
        return ""


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
