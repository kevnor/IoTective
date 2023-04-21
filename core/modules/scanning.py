#!/bin/pyhton3
from core.actions.nmap_host_enum import arp_scan, ping_scan, port_scan
from core.utils.host import is_root
from enum import Enum
from core.utils.models import Port, Host
from typing import List, Dict, Any
from rich.table import Table
from rich import box


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


def init_host(host: dict, host_key: Dict[str, Any]) -> Host:
    ip = host["ipv4"]
    mac = host.get("mac", "Unknown")
    vendor = host.get("vendor", "Unknown")
    if vendor == "Unknown":
        vendor = host_key.get(ip, {}).get("macaddress", {}).get("vendor", "Unknown")

    os = host_key.get(ip, {}).get("osmatch", [{}])[0].get("name", "Unknown")
    os_accuracy = host_key.get(ip, {}).get("osmatch", [{}])[0].get("accuracy", "Unknown")
    if ip in host_key:
        os_type = host_key.get(ip, {}).get("osmatch", [{}])[0].get("osclass", [{}]).get("type", "Unknown")
    else:
        os_type = "Unknown"

    return Host(ip=ip, mac=mac, vendor=vendor, os=os, os_accuracy=os_accuracy, os_type=os_type)


def init_port(port: dict) -> Port:
    protocol = port.get("protocol", "Unknown")
    port_id = port.get("portid", "Unknown")
    service_name = port.get("service", {}).get("name", "Unknown")
    product = port.get("service", {}).get("product", "Unknown")
    version = port.get("service", {}).get("version", "Unknown")
    cpe = [c.get("cpe", "Unknown") for c in port.get("cpe", [])]
    cves = []
    for script in port.get("scripts", {}):
        if script["name"] == "vulners":
            for cpe in script["data"]:
                for child in script["data"][cpe]["children"]:
                    cve = child
                    cve["cpe"] = cpe
                    cves.append(cve)
    return Port(
        protocol=protocol,
        port_id=port_id,
        service_name=service_name,
        product=product,
        version=version,
        cpe=cpe,
        cves=cves,
    )


def analyse_host(host: dict, scan_result, logger, console) -> Host:
    host = init_host(host, scan_result)
    console.print(host.colored(), justify="center")

    if host.ip in scan_result:
        table = Table(box=box.MINIMAL)

        table.add_column("Port", style="cyan")
        table.add_column("Service", style="blue")
        table.add_column("Product", style="red")
        table.add_column("Version", style="purple")
        table.add_column("CVEs", style="red")

        for port in scan_result[host.ip]["ports"]:
            port_info = init_port(port)
            table.add_row(
                port_info.port_id,
                port_info.service_name,
                port_info.product,
                port_info.version,
                str(len(port_info.cves)))
        console.print(table)
    return host
