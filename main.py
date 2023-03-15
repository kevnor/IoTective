#!/bin/pyhton3

from core.user import choose_nic, choose_targets, choose_zigbee_device
from core.utility import subnet_to_cidr
from core.scan_enum.enumeration import nmap_enumeration
import json
import os


def main():
    nic = choose_nic()

    path = os.getcwd().split("/")
    path.append("scans")
    path.append("scan.json")
    path = "/".join(path)

    # include_zigbee_scan = input("Include ZigBee scanning? (N, y) ")
    # zigbee_device = choose_zigbee_device()
    ip_range = nic['IPv4']['address'] + "/" + str(subnet_to_cidr(nic['IPv4']['netmask']))
    discovered_hosts = nmap_enumeration(ip_range)
    print(json.dumps(discovered_hosts, indent=4))

    with open(path, "w") as file:
        json.dump(discovered_hosts, file)

    # with open(path, 'r') as file:
    #     data = json.load(file)
    #     hosts = data["hosts"]
    #     if hosts:
    #         print(nmap_enumeration(hosts))
    # if discovered_hosts:
    #     chosen_targets = choose_targets()
    #     print(chosen_targets)
    # else:
    #     print("No hosts were found. Try another network interface.")


if __name__ == '__main__':
    main()
