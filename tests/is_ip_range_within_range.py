import ipaddress


def is_subnet(subnet, supernet):
    subnet = ipaddress.ip_network(subnet)
    supernet = ipaddress.ip_network(supernet)
    return subnet.subnet_of(supernet)


def is_ip_in_range(ip_address, ip_range):
    ip_address = ipaddress.ip_address(ip_address)
    ip_range = ipaddress.ip_network(ip_range)
    return ip_address in ip_range


def is_ip_range_within_range(subnet1, subnet2):
    return is_subnet(subnet1, subnet2) and is_subnet(subnet2, subnet1)


subnet1 = "192.168.1.0/24"
subnet2 = "192.168.0.0/16"

if is_ip_range_within_range(subnet1, subnet2):
    print(f"{subnet1} is within {subnet2}")
else:
    print(f"{subnet1} is not within {subnet2}")
