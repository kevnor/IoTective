#!/bin/pyhton3
# Modules:
import nmap3

# Functions:
from core.utils.formatting import format_vulns_scan


def nmap_cpe_scan(target):
    """Use the "vulners" nmap script to discover vulnerabilities based on the CPE of the running services"""
    """Returns a dictionary of ports and their CVEs as an array"""
    """Only ports with CPEs where CVEs are found are returned"""
    nmp = nmap3.Nmap()
    arguments = "-sV --open -T4 --script vulners"
    scan_result = nmp.nmap_version_detection(target=target, args=arguments)
    print(str(scan_result))

    return format_vulns_scan(ports=scan_result['scan'][target]['tcp'])