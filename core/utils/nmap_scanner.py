#!/bin/pyhton3
# Modules:
from configparser import ConfigParser
from nmap import PortScanner

# Functions:
from core.utils.formatting import subnet_to_cidr, format_discovered_ip_hosts, format_vulns_scan


def nmap_enumeration():
    nm = PortScanner()

    # Get network interface configuration
    config = ConfigParser()
    config.read("config.ini")
    nic = config["Network Interface"]
    ip_range = f"{nic['ipv4']}/{subnet_to_cidr(nic['netmask'])}"

    # Perform nmap scan on IP range of network interface
    print(f"Performing host discovery and port scanning on IP range {ip_range}...")
    arguments = "-n -sV --top-ports 10000 -T4 --open " + ip_range
    scan_results = nm.scan(arguments=arguments)

    return format_discovered_ip_hosts(scan_results=scan_results)


def nmap_cpe_scan(target):
    """Use the "vulners" nmap script to discover vulnerabilities based on the CPE of the running services"""
    """Returns a dictionary of ports and their CVEs as an array"""
    """Only ports with CPEs where CVEs are found are returned"""
    nm = PortScanner()
    arguments = "-sV --open -T4 --script vulners " + target
    scan_result = nm.scan(arguments=arguments)

    return format_vulns_scan(ports=scan_result['scan'][target]['tcp'])
