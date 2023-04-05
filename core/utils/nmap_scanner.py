#!/bin/pyhton3
# Modules:
from configparser import ConfigParser
from nmap import PortScanner

# Functions:
from core.utils.formatting import subnet_to_cidr


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
    output = {}

    # Extract useful information from the scan
    for host in scan_results["scan"]:
        if host in ["127.0.0.1"] or "mac" not in scan_results["scan"][host]["addresses"]:
            continue
        output[host] = {
            "addresses": scan_results["scan"][host]["addresses"],
            "vendor": {},
            "ports": {},
            "os": {}
        }
        if "vendor" in scan_results["scan"][host] and scan_results["scan"][host]["vendor"]:
            output[host]["vendor"] = scan_results["scan"][host]["vendor"][output[host]["addresses"]["mac"]]
        if "tcp" in scan_results["scan"][host] and scan_results["scan"][host]["tcp"]:
            output[host]["ports"] = scan_results["scan"][host]["tcp"]
        if "osmatch" in scan_results["scan"][host] and scan_results["scan"][host]["osmatch"]:
            output[host]["os"] = scan_results["scan"][host]["osmatch"]
    return output


def nmap_cpe_scan(target):
    """Use the "vulners" nmap script to discover vulnerabilities based on the CPE of the running services"""
    """Returns a dictionary of ports and their CVEs as an array"""
    """Only ports with CPEs where CVEs are found are returned"""
    # {
    #     22: [
    #         {
    #             "name": "CVE-2021-28041",
    #             "score": "4.6",
    #             "url": "https://vulners.com/cve/CVE-2021-28041",
    #         },
    #         {
    #             "name": "CVE-2021-41617",
    #             "score": "4.4",
    #             "url": "https://vulners.com/cve/CVE-2021-41617",
    #         }
    #     ],
    #     80: [
    #         {
    #             "name": "CVE-2022-22707",
    #             "score": "4.3",
    #             "url": "https://vulners.com/cve/CVE-2022-22707",
    #         }
    #     ],
    # }

    nm = PortScanner()
    arguments = "-sV --open -T4 --max-parallelism 10 --script vulners " + target
    scan_result = nm.scan(arguments=arguments)
    port_cves = {}

    for port in scan_result['scan'][target]['tcp']:
        if 'script' in scan_result['scan'][target]['tcp'][port] \
                and 'vulners' in scan_result['scan'][target]['tcp'][port]['script']:
            formatted_cves = []
            output = scan_result['scan'][target]['tcp'][port]['script']['vulners']
            nl = "\n"
            output = output.split(''.join(nl))
            cves = output[2:]
            tab = '\t'
            for cve in cves:
                cve_data = cve.split(''.join(tab))
                formatted_cve = {
                    'name': cve_data[1],
                    'score': cve_data[2],
                    'url': cve_data[3]
                }
                formatted_cves.append(formatted_cve)
            port_cves[port] = formatted_cves
    return port_cves
