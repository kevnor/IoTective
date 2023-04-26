#!/bin/pyhton3
from core.actions.nmap_host_enum import arp_scan, port_scan
from core.utils.models import Host, init_port, init_host
from typing import List, Any
from core.utils.console import make_header, print_arp_scan_hosts, make_host_scan_layout, make_host_info, make_port_info


def scan_target(target: str, console: Any, logger: Any) -> List[Host]:
    """Perform a scan on the specified target.

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
                port_scan_result = port_scan(target=host["ipv4"], logger=logger)
                analysed_hosts.append(
                    analyse_host(
                        host=host,
                        scan_result=port_scan_result,
                        console=console,
                        logger=logger
                    )
                )
            except Exception as e:
                logger.error(f"Port scan for host {host} failed: {str(e)}")
                analysed_hosts.append(Host(ip=host["ipv4"], mac=host["mac"], vendor=host["vendor"]))
    else:
        console.info("Could not find any hosts using ARP scan")
    return analysed_hosts


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
