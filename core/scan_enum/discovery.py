from scapy.layers.l2 import srp, Ether, ARP
import serial
import json

ser = serial.Serial


def discover_ips(ip_range):
    # Perform ARP scan on IP range
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=2, verbose=0)

    discovered_hosts = []
    for element in ans:
        print(element)
        discovered_hosts.append({"ipv4": element[1].psrc, "mac": element[1].hwsrc})

    # Write IPv4 and MAC to JSON file
    with open("../../scans/scan.json", 'r') as file:
        data = json.load(file)

    data['hosts'] = discovered_hosts

    with open("../../scans/scan.json", 'w') as file:
        json.dump(data, file)

    return discovered_hosts


discover_ips('192.168.0.0/24')
