#!/bin/pyhton3
from core.actions.nmap_host_enum import arp_scan, port_scan
from core.utils.models import Host, init_port, update_host
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
                port_scan_result = port_scan(target=host.ip, logger=logger)
                # Add information from port scan to host
                analysed_host = analyse_host(
                        host=host,
                        scan_result=port_scan_result,
                        console=console,
                        logger=logger
                    )
                analysed_hosts.append(analysed_host)
            except Exception as e:
                logger.error(f"Port scan for host {host.ip} failed: {str(e)}")
                analysed_hosts.append(host)
    else:
        console.info("Could not find any hosts using ARP scan")
    return analysed_hosts


def analyse_host(host: Host, scan_result: dict, logger, console) -> Host:
    updated_host = host
    layout = make_host_scan_layout()
    layout["header"].update(make_header(host_ip=host.ip))

    # Add host information from port scan
    if host.ip in scan_result:
        updated_host = update_host(host=host, data=scan_result[host.ip])
        ports = [init_port(port) for port in scan_result[updated_host.ip]["ports"]]
        for port in ports:
            updated_host.add_port(port)

    layout["ports"].update(make_port_info(ports=updated_host.ports))
    layout["info"].update(make_host_info(host=updated_host))
    console.print(layout)
    return updated_host
