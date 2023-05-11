import psutil
import ipaddress
from pyroute2 import IW
from pyroute2 import IPRoute
from pyroute2.netlink import NetlinkError


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


