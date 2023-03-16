#!/bin/pyhton3
from nmap import PortScanner
from core.host import get_default_gateway
from configparser import ConfigParser
from core.utility import subnet_to_cidr
import asyncio
from bleak import BleakScanner


# Nmap is used to discover open ports and detect OS
def nmap_enumeration():
    nm = PortScanner()

    # Get network interface configuration
    config = ConfigParser()
    config.read("config.ini")
    nic = config["Network Interface"]
    ip_range = nic['ipv4'] + "/" + str(subnet_to_cidr(nic['netmask']))

    # Perform nmap scan on IP range of network interface
    print("Performing host discovery and port scanning on " + ip_range + "...")
    arguments = "-n -PE -PS80,3389,443 -PU40125,161 -PA21 --source-port 53 -v -T4 " + ip_range
    scan_results = nm.scan(arguments=arguments)
    output = {}
    default_gateway = get_default_gateway()

    # Extract useful information from the scan
    for host in scan_results['scan']:
        if host == '127.0.0.1' or host == default_gateway or "mac" not in scan_results['scan'][host]['addresses']:
            continue
        output[host] = {'addresses': scan_results['scan'][host]['addresses'], 'vendor': {}, 'ports': {}, 'os': {}}
        if 'vendor' in scan_results['scan'][host] and scan_results['scan'][host]['vendor']:
            output[host]['vendor'] = scan_results['scan'][host]['vendor'][output[host]['addresses']['mac']]
        if 'tcp' in scan_results['scan'][host] and scan_results['scan'][host]['tcp']:
            output[host]['ports'] = scan_results['scan'][host]['tcp']
        if 'osmatch' in scan_results['scan'][host] and scan_results['scan'][host]['osmatch']:
            output[host]['os'] = scan_results['scan'][host]['osmatch']
    return output


async def bluetooth_enumeration():
    devices = await BleakScanner.discover()
    for d in devices:
        print(d)

asyncio.run(bluetooth_enumeration())
