#!/bin/pyhton3
from core.actions.nmap_host_enum import arp_scan, ping_scan, port_scan
from core.utils.host import is_root
from enum import Enum
from core.utils.models import Host, init_port, init_host
from typing import List, Dict, Any

from core.utils.console import make_header, make_host_scan_layout, make_host_info, make_port_info


class ScanType(Enum):
    Ping = 0
    ARP = 1


class ScanMode(Enum):
    Normal = 0
    Noise = 1
    Evade = 2


def get_scan_type(args: Any, logger: Any) -> ScanType:
    scan_type = ScanType.Ping
    if args.scan_type == "arp":
        if not is_root():
            logger.warning("You need to be root in order to run arp scan.")
        else:
            scan_type = ScanType.ARP
    elif not args.scan_type:
        if is_root():
            scan_type = ScanType.ARP
    return scan_type


def scan_target(args: Any, target: str, scan_type: ScanType, console: Any, logger: Any) -> List[Host]:
    """Perform a scan on the specified target.

    Args:
        args (Any): Arguments for the scan.
        target (str): The IP address or CIDR range to scan.
        scan_type (ScanType): The type of scan to perform.
        console (Any): The console object to use for displaying the results.
        logger (Any): The logger object to use for logging.

    Returns:
        List[Host]: A list of Host objects representing each scanned host.
    """
    # Discover live hosts
    live_hosts = discover_hosts(target=target, logger=logger, scan_type=scan_type)
    analysed_hosts = []

    # Perform a port scan on each live host and analyse the results
    for host in live_hosts:
        try:
            port_scan_result = port_scan(target=host["ipv4"], logger=logger)
            analysed_hosts.append(analyse_host(host=host, scan_result=port_scan_result, console=console, logger=logger))
        except Exception as e:
            logger.error(f"Port scan for host {host} failed: {str(e)}")
            continue
    return analysed_hosts


def discover_hosts(target: str, logger: Any, scan_type: ScanType = ScanType.ARP) -> List[Dict[str, str]]:
    """Discover live hosts on the specified target.

    Args:
        target (str): The IP address or CIDR range to scan.
        logger (Any): The logger object to use for logging.
        scan_type (ScanType, optional): The type of scan to perform. Defaults to ScanType.ARP.

    Returns:
        List[Dict[str, str]]: A list of live hosts, each represented as a dictionary with keys
        'ipv4', 'mac', and 'vendor'.
    """
    if scan_type == ScanType.ARP:
        live_hosts = arp_scan(target=target, logger=logger)
    else:
        live_hosts = ping_scan(target=target, logger=logger)
    return live_hosts


def analyse_host(host: dict, scan_result, logger, console) -> Host:
    host = init_host(host, scan_result)

    if host.ip in scan_result:
        ports = [init_port(port) for port in scan_result[host.ip]["ports"]]
        layout = make_host_scan_layout(port_size=len(ports))

        layout["header"].update(make_header(host_ip=host.ip))
        layout["info"].update(make_host_info(host=host))
        layout["ports"].update(make_port_info(ports=ports))

        console.print(layout)
    return host
