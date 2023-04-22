import ipaddress

ip = '192.168.2.100'
subnet = '192.168.1.0/24'

ip_address = ipaddress.ip_address(ip)
network = ipaddress.ip_network(subnet)

if ip_address in network:
    print(f"The IP address {ip} is in the subnet {subnet}.")
else:
    print(f"The IP address {ip} is not in the subnet {subnet}.")
