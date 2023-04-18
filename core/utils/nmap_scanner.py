#!/bin/pyhton3
# Modules:
from core.utils.directory import get_config
import nmap3

# Functions:
from core.utils.formatting import subnet_to_cidr, format_discovered_ip_hosts, format_vulns_scan


def nmap_enumeration():
    nmp = nmap3.Nmap()

    # Get network interface configuration
    config, config_file = get_config()
    config.read("config.ini")
    ip = config.get("Network Interface", "ipv4")
    netmask = config.get("Network Interface", "netmask")
    ip_range = f"{ip}/{subnet_to_cidr(netmask)}"

    # Perform nmap scan on IP range of network interface
    arguments = "-n -sV --top-ports 10000 -T4 --open"
    results = nmp.nmap_version_detection(target=ip_range, args=arguments)
    print(str(results))
    return format_discovered_ip_hosts(scan_results=results)


def nmap_cpe_scan(target):
    """Use the "vulners" nmap script to discover vulnerabilities based on the CPE of the running services"""
    """Returns a dictionary of ports and their CVEs as an array"""
    """Only ports with CPEs where CVEs are found are returned"""
    nmp = nmap3.Nmap()
    arguments = "-sV --open -T4 --script vulners"
    scan_result = nmp.nmap_version_detection(target=target, args=arguments)
    print(str(scan_result))

    return format_vulns_scan(ports=scan_result['scan'][target]['tcp'])
