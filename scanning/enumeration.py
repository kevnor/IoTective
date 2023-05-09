#!/bin/pyhton3
from .nmap import arp_scan, port_scan
from .utilities import analyse_host
from models.host import Host
from typing import List, Any
from reporting.console import print_arp_scan_hosts


def scan_ip_range(target: str, console: Any, logger: Any) -> List[dict]:
    """Perform a scan on the specified IP range.

    Args:
        target (str): The IP address or CIDR range to scan.
        console (Any): The console object to use for displaying the results.
        logger (Any): The logger object to use for logging.

    Returns:
        List[Host]: A list of Host objects representing each scanned host.
    """
    analysed_hosts = []

    # Discover live hosts
    live_hosts = arp_scan(target=target, logger=logger)
    if len(live_hosts) > 0:
        print_arp_scan_hosts(hosts=live_hosts, console=console)

        # Perform a port scan on each live host and analyse the results
        for host in live_hosts:
            try:
                port_scan_result = port_scan(target=host.ip, logger=logger)
                # Add information from port scan to host
                analysed_host = analyse_host(
                        host=host,
                        scan_result=port_scan_result,
                        console=console,
                        logger=logger
                    )
                analysed_hosts.append(analysed_host.as_dict())
            except Exception as e:
                logger.error(f"Port scan for host {host.ip} failed: {str(e)}")
                analysed_hosts.append(host.as_dict())
    else:
        console.info("Could not find any hosts using ARP scan")
    return analysed_hosts
