#!/bin/pyhton3
from sniffing.sniffing import sniffing
from initialization.config import configure
from scanning.enumeration import scan_ip_range
from initialization.logger import MyLogger
from rich.console import Console
from scanning.hue import discover_philips_hue_bridge
import asyncio
from app.app import IoTective


async def main():
    logger = MyLogger(__name__)
    console = Console()

    # Phase 1: Initialization
    init_data = configure(logger=logger, console=console)
    logger.info("Starting IoTective scanner...")
    if init_data != {} and init_data["ip_range"] != "":
        # Phase 2: Scanning
        #hosts = scan_ip_range(target=init_data["ip_range"], logger=logger, console=console)

        # Identify Philips Hue bridges on the network
        #hue_bridges = discover_philips_hue_bridge(logger=logger, console=console)

        # Phase 3: Sniffing
        wireless_hosts = await sniffing(init_data=init_data, logger=logger, console=console)
    else:
        logger.error("Failed to determine target IP range")


if __name__ == "__main__":
    try:
        app = IoTective()
        app.run()
        #asyncio.run(main())
    except KeyboardInterrupt:
        raise SystemExit("\nCtrl+C pressed. Exiting.")
