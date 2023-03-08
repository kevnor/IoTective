#!/bin/pyhton3

from nmap import PortScanner
from core.host import get_default_gateway


# Nmap is used to discover open ports and detect OS
def nmap_enumeration(hosts):
    nm = PortScanner()
    print("Performing OS detection and scanning of " + ip + "/" + str(netmask_cidr))
    arguments = "-sS -sV -Pn -T4 -p- --osscan-limit --open " + ip + "/" + str(netmask_cidr)
    scan_results = nm.scan(arguments=arguments)
    output = {}
    default_gateway = get_default_gateway()

    # Extract useful information from the scan
    for host in scan_results['scan']:

        if host == '127.0.0.1' or host == default_gateway:
            continue
        output[host] = {'addresses': scan_results['scan'][host]['addresses'], 'vendor': {}, 'ports': {}, 'os': {}}

        if 'vendor' in scan_results['scan'][host] and scan_results['scan'][host]['vendor']:
            output[host]['vendor'] = scan_results['scan'][host]['vendor'][output[host]['addresses']['mac']]
        if 'tcp' in scan_results['scan'][host] and scan_results['scan'][host]['tcp']:
            output[host]['ports'] = scan_results['scan'][host]['tcp']
        if 'osmatch' in scan_results['scan'][host] and scan_results['scan'][host]['osmatch']:
            output[host]['os'] = scan_results['scan'][host]['osmatch']
    return output

