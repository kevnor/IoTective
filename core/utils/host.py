from __future__ import print_function
import socket
import psutil
import netifaces
import subprocess
from configparser import ConfigParser
import os


def get_default_gateway():
    gws = netifaces.gateways()
    gateway = gws['default'][netifaces.AF_INET][0]
    return gateway


af_map = {
    socket.AF_INET: 'IPv4',
    socket.AF_INET6: 'IPv6',
    psutil.AF_LINK: 'MAC',
}

duplex_map = {
    psutil.NIC_DUPLEX_FULL: "full",
    psutil.NIC_DUPLEX_HALF: "half",
    psutil.NIC_DUPLEX_UNKNOWN: "?",
}


# Finds and prints all network interfaces
def get_nics():
    count = 0
    nics_dict = {}

    for nic, addrs in psutil.net_if_addrs().items():

        # Skips NICs that use IP addresses used for loopback or failed to obtain from DHCP
        unreachable_ip = False
        for addr in addrs:
            if addr.address.startswith("169.254.") or addr.address == "127.0.0.1":
                unreachable_ip = True
                break
        if unreachable_ip:
            continue

        count = count + 1
        nic_dict = {"name": nic}
        print("%s:" % ("(" + str(count) + ") " + nic))
        for addr in addrs:
            addr_dict = {"address": addr.address}
            addr_family = af_map.get(addr.family, addr.family)

            print("    %-4s" % addr_family, end="")
            print(" address   : %s" % addr.address)
            if addr.broadcast:
                addr_dict["broadcast"] = addr.broadcast
                print("         broadcast : %s" % addr.broadcast)
            if addr.netmask:
                addr_dict["netmask"] = addr.netmask
                print("         netmask   : %s" % addr.netmask)
            if addr.ptp:
                addr.ptp["p2p"] = addr.ptp
                print("      p2p       : %s" % addr.ptp)
            nic_dict[af_map.get(addr.family, addr.family)] = addr_dict
        print("")
        nics_dict[count] = nic_dict
    return nics_dict


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


def get_interface_name():
    config_file = os.path.join(os.path.dirname(__file__), "../../config.ini")
    config = ConfigParser()
    config.read(config_file)

    return config.get("Network Interface", "name")


def get_wireless_mode():
    # Run the iwconfig command and capture the output
    completed_process = subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Check if there was an error running the command
    if completed_process.returncode != 0:
        print(f"Error running iwconfig: {completed_process.stderr.decode().strip()}")
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


def set_wireless_mode(new_mode="Monitor"):
    current_mode = get_wireless_mode()
    interface = get_interface_name()

    if current_mode == new_mode:
        return True
    else:
        try:
            subprocess.check_call(["sudo", "ifconfig", interface, "down"])
            subprocess.check_call(["sudo", "iwconfig", interface, "mode", "monitor"])
            subprocess.check_call(["sudo", "ifconfig", interface, "up"])

            subprocess.check_call(["sudo", "iw", "dev", interface, "set", "type", new_mode])
            print(f"Wireless mode set to {new_mode}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error setting wireless mode: {e}")
            return False
