from enum import Enum
from typing import List
from core.utils.directory import get_config
from nmap3 import Nmap, NmapHostDiscovery, NmapScanTechniques

# Functions:
from core.utils.formatting import subnet_to_cidr, parse_scan_results
from core.utils.host import is_root


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


def ping_scan(target: str) -> List[str]:
    """Perform a ping scan on the specified targets."""
    nmp = NmapScanTechniques()
    result = nmp.nmap_ping_scan(target=target)
    live_hosts = [host for host in result if result[host]['status']['state'] == 'up']
    return live_hosts


def arp_scan(target: str) -> List[str]:
    """Perform an ARP scan on the specified targets."""
    nmp = NmapHostDiscovery()
    result = nmp.nmap_arp_discovery(target=target, args="-sn")
    live_hosts = [host for host in result if 'state' in result[host] and result[host]['state']['state'] == 'up']
    return live_hosts


def port_scan(target: str, log) -> List:
    log.logger("info", f"Scanning {target} for open ports ...")
    try:
        if is_root():
            log.logger("info", f"Scanning {target} for known vulnerabilities ...")
            nmp = Nmap()
            arguments = "--open -T4 -O --script vulners"
            return nmp.nmap_version_detection(target=target, args=arguments)
        else:
            nmp = NmapHostDiscovery()
            return nmp.nmap_portscan_only(target=target, args="--host-timeout 240 -T4 --open")
    except Exception as e:
        raise SystemExit(f"Error: {e}")

