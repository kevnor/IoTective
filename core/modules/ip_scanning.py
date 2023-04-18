#!/bin/pyhton3
from core.vendors.hue import discover_philips_hue_bridge
from core.utils.nmap_scanner import nmap_enumeration, nmap_cpe_scan
from rich.console import Console


# Main function for performing discovery/scanning/enumeration
def ip_scanning():
    # Discover and enumerate hosts on local IP network
    ip_network = nmap_enumeration()
    console = Console()

    console.status("Performing CPE lookup to discover CVEs...")
    # CPE lookup for corresponding CVEs
    for host in ip_network:
        console.status(f"Scanning {host}...")
        ports = nmap_cpe_scan(host)
        for port in ports:
            ip_network[host]["ports"][port]["vulns"] = ports[port]

    console.status("Scanning for Philips Hue bridge")
    # Discover Philips Hue bridge
    discovered_bridges = discover_philips_hue_bridge()
    if len(discovered_bridges) > 0:
        console.status(f"{len(discovered_bridges)} Philips Hue bridge(s) [green]discovered[/green]")
    else:
        console.status(f"Philips Hue bridge [red]not discovered[/green]")
    for bridge in discovered_bridges:
        if bridge in ip_network:
            ip_network[bridge]["bridge"] = vars(discovered_bridges[bridge])
        else:
            ip_network[discovered_bridges[bridge]["ip"]] = {"bridge": vars(discovered_bridges[bridge])}
    return ip_network
