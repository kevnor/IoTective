import asyncio
import datetime
import logging
import pathlib
from logging.handlers import RotatingFileHandler

from core.actions.ble_enumeration import bluetooth_enumeration
from core.actions.packet_capture import wifi_sniffing
from core.modules.scanning import ip_scanning
from core.utils.directory import create_scan_file, get_config
from core.utils.formatting import subnet_to_cidr


def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler = RotatingFileHandler('scan.log', mode='a', maxBytes=5 * 1024 * 1024, backupCount=2, encoding=None, delay=0)
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)
    logger = logging.getLogger()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.setLevel(logging.INFO)


async def scan_ip_network(ip, netmask):
    ip_range = f"{ip}/{subnet_to_cidr(netmask)}"
    logging.info(f"Performing host discovery and port scanning on IP range {ip_range}...")
    hosts = await ip_scanning()
    logging.info(f"Discovered {len(hosts)} hosts using nmap")
    return hosts


async def main():
    config, config_file = get_config()
    setup_logging()

    data, path = create_scan_file()
    logging.info(f"Created scan file at '{path}'")

    tasks = []

    # Enumerate devices on the network using nmap
    if config.getboolean("Scan Types", "ip_network"):
        ip = config.get("Network Interface", "ipv4")
        netmask = config.get("Network Interface", "netmask")
        tasks.append(asyncio.create_task(scan_ip_network(ip, netmask)))

    # Determine connectivity method (wired/Wi-Fi) for IP network devices through packet sniffing
    if config.getboolean("Scan Types", "wifi_sniffing"):
        tasks.append(asyncio.create_task(wifi_sniffing()))

    # Discover and enumerate ble devices
    if config.getboolean("Scan Types", "ble"):
        tasks.append(asyncio.create_task(bluetooth_enumeration()))

    await asyncio.gather(*tasks)

    data["scan_end"] = str(datetime.datetime.now())
    logging.info(f"Scan finished at {data['scan_end']}")


