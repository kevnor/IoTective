#!/bin/pyhton3
from core.vendors.hue import discover_philips_hue_bridge
from core.actions.nmap_host_enum import nmap_enumeration, arp_scan, ping_scan, port_scan
from core.utils.host import is_root
import logging
from rich.logging import RichHandler
from rich.console import Console
from enum import Enum
from core.utils.models import Port, Host
from typing import List, Tuple, Dict, Any

# Main function for performing discovery/scanning/enumeration
def ip_scanning():
    FORMAT = "%(message)s"
    logging.basicConfig(
        level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
    )

    log = logging.getLogger("rich")

    # Discover and enumerate hosts on local IP network
    ip_network = nmap_enumeration()
    console = Console()

    console.status("Performing CPE lookup to discover CVEs...")
    # CPE lookup for corresponding CVEs
    # for host in ip_network:
    #     console.status(f"Scanning {host}...")
    #     ports = nmap_cpe_scan(host)
    #     for port in ports:
    #         ip_network[host]["ports"][port]["vulns"] = ports[port]

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


class ScanType(Enum):
    Ping = 0
    ARP = 1


class ScanMode(Enum):
    Normal = 0
    Noise = 1
    Evade = 2


def get_scan_type(args: Any, log: Any) -> ScanType:
    scan_type = ScanType.Ping
    if args.scan_type == "arp":
        if not is_root():
            log.logger("warning", "You need to be root in order to run arp scan.")
        else:
            scan_type = ScanType.ARP
    elif not args.scan_type:
        if is_root():
            scan_type = ScanType.ARP
    return scan_type


def get_scan_mode(args: Any, log: Any) -> ScanMode:
    scan_mode = ScanMode.Normal
    if args.mode == "evade":
        if is_root():
            log.logger("info", "Evasion mode enabled!")
            scan_mode = ScanMode.Evade
        else:
            log.logger(
                "error",
                "You must be root to use evasion mode!"
                + " Using normal mode ...",
            )
    elif args.mode == "noise":
        log.logger("info", "Noise mode enabled!")
        scan_mode = ScanMode.Noise
    return scan_mode


def scan(args: Any, target: str, scan_type: ScanType, scan_mode: ScanMode, console: Any, log: Any) -> List[Host]:
    live_hosts = discover_hosts(target, console, scan_type)
    analysed_hosts = []

    for host in live_hosts:
        try:
            port_scan_result = port_scan(target=host, log=log)
            analysed_hosts.append(analyse_host(host, port_scan_result, console, log))
        except Exception as e:
            log.logger("error", f"Port scan for host {host} failed: {str(e)}")
            continue
    return analysed_hosts


def discover_hosts(target: str, console: Any, scan_type: ScanType = ScanType.ARP) -> List[str]:
    if scan_type == ScanType.ARP:
        live_hosts = arp_scan(target)
    else:
        live_hosts = ping_scan(target)
    return live_hosts


def init_host(host_ip: str, host_key: Dict[str, Any]) -> Host:
    try:
        ip = host_ip
    except (KeyError, IndexError):
        ip = "Unknown"

    try:
        mac = host_key[host_ip]["macaddress"]["addr"]
    except (KeyError, IndexError):
        mac = "Unknown"

    try:
        vendor = host_key[host_ip]["macaddress"]["vendor"]
    except (KeyError, IndexError):
        vendor = "Unknown"

    try:
        os = host_key[host_ip]["osmatch"][0]["name"]
    except (KeyError, IndexError):
        os = "Unknown"

    try:
        os_accuracy = host_key[host_ip]["osmatch"][0]["accuracy"]
    except (KeyError, IndexError):
        os_accuracy = "Unknown"

    try:
        os_type = host_key[host_ip]["osmatch"][0]["osclass"][0]["type"]
    except (KeyError, IndexError):
        os_type = "Unknown"

    return Host(
        ip=ip,
        mac=mac,
        vendor=vendor,
        os=os,
        os_accuracy=os_accuracy,
        os_type=os_type,
    )


def init_port(port) -> Port:
    try:
        protocol = port["protocol"]
    except (KeyError, IndexError):
        protocol = "Unknown"

    try:
        port_id = port["portid"]
    except (KeyError, IndexError):
        port_id = "Unknown"

    try:
        service_name = port["service"]["name"]
    except (KeyError, IndexError):
        service_name = "Unknown"

    try:
        product = port["service"]["product"]
    except (KeyError, IndexError):
        product = "Unknown"

    try:
        version = port["service"]["version"]
    except (KeyError, IndexError):
        version = "Unknown"

    try:
        cpe = []
        for c in port["cpe"]:
            cpe.append(c["cpe"])
    except (KeyError, IndexError):
        cpe = "Unknown"

    return Port(
        protocol=protocol,
        port_id=port_id,
        service_name=service_name,
        product=product,
        version=version,
        cpe=cpe
    )


def analyse_host(host_ip, scan_result, log, console) -> Host:
    host = init_host(host_ip, scan_result)

    for port in scan_result[host.ip]["ports"]:
        port_info = init_port(port)
        host.add_port(port_info)

    return host
