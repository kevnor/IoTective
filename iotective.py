#!/bin/pyhton3
from core.modules.scanning import scan_target
from core.modules.sniffing import sniffing
from core.modules.initialization import initialize
from core.utils.logger import MyLogger
from rich.console import Console
from core.vendors.hue import discover_philips_hue_bridge
import asyncio


async def main():
    logger = MyLogger(__name__)
    console = Console()

    logger.info("Starting IoTective scanner...")
    init_data = initialize(logger=logger, console=console)

    if init_data["ip_range"] is not "":
        hosts = scan_target(target=init_data["ip_range"], logger=logger, console=console)

        # Identify Philips Hue bridges on the network
        hue_bridges = discover_philips_hue_bridge(logger=logger, console=console)

        # Capture packets to identify wireless hosts
        wireless_hosts = await sniffing(init_data=init_data, logger=logger, console=console)
    else:
        logger.error("Failed to determine target IP range")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        raise SystemExit("\nCtrl+C pressed. Exiting.")
