import psutil
import ipaddress


def get_private_network_interfaces():
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
                'name': int_face,
                'ip_address': ip_address,
                'netmask': addr.netmask,
            })

    return int_faces


if __name__ == '__main__':
    interfaces = get_private_network_interfaces()

    if not interfaces:
        print('No interfaces found on a private network.')
    else:
        print('Interfaces on a private network:')
        for iface in interfaces:
            print(f"Name: {iface['name']}, IP: {iface['ip_address']}, Netmask: {iface['netmask']}")
