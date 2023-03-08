#!/bin/pyhton3

from core.user import choose_nic, choose_targets
from core.scan_enum.discovery import discover_ips
from core.utility import subnet_to_cidr
import json


def main():
    nic = choose_nic()
    ip_range = nic['IPv4']['address'] + "/" + subnet_to_cidr(nic['IPv4']['netmask'])
    discovered_hosts = discover_ips(ip_range)
    if discovered_hosts:
        chosen_targets = choose_targets(discovered_hosts)
        print(chosen_targets)
    else:
        print("No hosts were found. Try another network interface.")


if __name__ == '__main__':
    main()
