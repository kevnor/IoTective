from enum import Enum
from typing import List, Dict
from nmap3 import Nmap, NmapHostDiscovery, NmapScanTechniques, NmapExecutionError, NmapNotInstalledError

# Functions:
from core.utils.formatting import subnet_to_cidr, parse_scan_results
from core.utils.host import is_root
from core.utils.directory import get_config


class ScanMode(Enum):
    Normal = 0
    Noise = 1
    Evade = 2


def nmap_enumeration():
    nmp = Nmap()

    # Get network interface configuration
    config, config_file = get_config()
    config.read("config.ini")
    ip = config.get("Network Interface", "ipv4")
    netmask = config.get("Network Interface", "netmask")
    ip_range = f"{ip}/{subnet_to_cidr(netmask)}"

    # Perform nmap scan on IP range of network interface
    arguments = "-n -sV --top-ports 10000 -T4 --open"
    results = nmp.nmap_version_detection(target=ip_range, args=arguments)
    return parse_scan_results(scan_results=results)


def get_live_hosts(scan_results: Dict) -> List[Dict[str, str]]:
    """
    Extract live hosts from Nmap scan results.

    Args:
        scan_results (Dict): The Nmap scan results.

    Returns:
        List[Dict[str, str]]: A list of live hosts, each represented as a dictionary with keys
        'ipv4', 'mac', and 'vendor'.
    """
    live_hosts = []
    for host, host_info in scan_results.items():
        if 'state' in host_info and host_info['state']['state'] == 'up':
            if 'macaddress' in host_info and host_info['macaddress'] is not None:
                mac_address = host_info['macaddress'].get('addr', 'Unknown')
                vendor = host_info['macaddress'].get('vendor', 'Unknown')
            else:
                mac_address = 'Unknown'
                vendor = 'Unknown'
            live_hosts.append({
                'ipv4': host,
                'mac': mac_address,
                'vendor': vendor
            })
    return live_hosts


def ping_scan(target: str, logger) -> List[Dict[str, str]]:
    """
    Perform a ping scan on the specified targets.

    Args:
        target (str): The IP address or CIDR range to scan.
        logger: The logger to use for logging.

    Returns:
        List[Dict[str, str]]: A list of live hosts, each represented as a dictionary with keys
        'ipv4', 'mac', and 'vendor'.
    """
    nmp = NmapScanTechniques()
    logger.info(f"Performing Ping scan on {target}")
    result = nmp.nmap_ping_scan(target=target)
    live_hosts = get_live_hosts(result)

    if live_hosts:
        logger.info(f"Found {len(live_hosts)} live hosts")
    else:
        logger.info(f"Could not find any live hosts")

    return live_hosts


def arp_scan(target: str, logger) -> List[Dict[str, str]]:
    """
    Perform an ARP scan on the specified target.

    Args:
        target (str): The IP address or CIDR range to scan.
        logger: The logger to use for logging.

    Returns:
        List[Dict[str, str]]: A list of live hosts, each represented as a dictionary with keys
        'ipv4', 'mac', and 'vendor'.
    """
    nmp = NmapHostDiscovery()
    logger.info(f"Performing ARP scan on {target}")
    result = nmp.nmap_arp_discovery(target=target, args="-sn")
    live_hosts = get_live_hosts(result)

    if live_hosts:
        logger.info(f"Found {len(live_hosts)} live hosts")
    else:
        logger.info(f"Could not find any live hosts")

    return live_hosts


def port_scan(target: str, logger) -> List:
    try:
        if is_root():
            logger.info(f"Scanning {target} for ports and known vulnerabilities ...")
            nmp = Nmap()
            arguments = "--open -T4 -O --top-ports 10000 --script vulners"
            results = nmp.nmap_version_detection(target=target, args=arguments)

            return results
        else:
            logger.info(f"Scanning {target} for open ports ...")
            nmp = NmapHostDiscovery()
            return nmp.nmap_portscan_only(target=target, args="--host-timeout 240 -T4 --open")
    except NmapNotInstalledError as e:
        logger.error(f"Installation error in nmap command: {e}")
        return []
    except NmapExecutionError as e:
        logger.error(f"Error running nmap: {e}")
        return []
    except Exception as e:
        logger.error(f"Unknown error occurred: {e}")
        return []

