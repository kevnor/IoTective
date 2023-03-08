from __future__ import print_function
import socket
import psutil
import netifaces


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
    for i in df.split(b'\n'):
        if i:
            info = device_re.match(i)
            if info:
                dinfo = info.groupdict()
                dinfo['device'] = '/dev/bus/usb/%s/%s' % (dinfo.pop('bus'), dinfo.pop('device'))
                devices.append(dinfo)
    return devices


print(str(get_usb_devices()))
