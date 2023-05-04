from typing import List
from nmap3 import Nmap, NmapHostDiscovery, NmapExecutionError, NmapNotInstalledError
from core.utils.models import Host


def arp_scan(target: str, logger) -> List[Host]:
    """
    Perform an ARP scan on the specified target.

    Args:
        target (str): The IP address or CIDR range to scan.
        logger: The logger to use for logging.

    Returns:
        List[Host]: A list of live hosts, each represented as a Host object.
    """
    nmp = NmapHostDiscovery()
    logger.info(f"Performing ARP scan on {target}...")
    result = nmp.nmap_arp_discovery(target=target, args="-sn")
    live_hosts = [
        Host(
            ip=host,
            mac=host_info.get('macaddress', {}).get('addr', 'Unknown'),
            vendor=host_info.get('macaddress', {}).get('vendor', 'Unknown')
        )
        for host, host_info in result.items()
        if 'state' in host_info and host_info['state'].get('state') == 'up' and host_info['macaddress'] is not None
    ]

    if live_hosts:
        logger.info(f"Found {len(live_hosts)} live hosts")
    else:
        logger.info(f"Could not find any live hosts")

    return live_hosts


def port_scan(target: str, logger) -> dict:
    try:
        logger.info(f"Scanning {target} for open ports, services, and known vulnerabilities ...")
        nmp = Nmap()
        arguments = "--open -T4 -O --top-ports 100 --script vulners"
        return nmp.nmap_version_detection(target=target, args=arguments)
    except NmapNotInstalledError as e:
        logger.error(f"Installation error in nmap command: {e}")
    except NmapExecutionError as e:
        logger.error(f"Error running nmap: {e}")
    except Exception as e:
        logger.error(f"Unknown error occurred: {e}")
    return {}
