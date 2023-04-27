#!/bin/pyhton3
from core.modules.scanning import scan_target
from core.modules.sniffing import sniff_wifi
from core.utils.logger import MyLogger
from core.utils.host import get_ip_range, is_root
from rich.console import Console
from core.vendors.hue import discover_philips_hue_bridge
import asyncio


async def main():
    logger = MyLogger(__name__)
    console = Console()
    await sniff_wifi(ip_range="10.0.0.0/24", console=console, logger=logger)
    return

    if not is_root():
        logger.error("You need to run the script as root!")
        logger.info("Quitting...")
        return

    logger.info("Starting IoTective scanner...")

    # Perform nmap scans to discover hosts on the network and find open ports
    target = get_ip_range(logger=logger, console=console)

    if target is not None:
        hosts = scan_target(target=target, logger=logger, console=console)

        # Identify Philips Hue bridges on the network
        hue_bridges = discover_philips_hue_bridge(logger=logger, console=console)

        # Capture packets to identify wireless hosts
        # wifi_hosts = await sniff_wifi(ip_range=target, logger=logger, console=console)
    else:
        logger.error("Failed to determine target IP range")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        raise SystemExit("\nCtrl+C pressed. Exiting.")
