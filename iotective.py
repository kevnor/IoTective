#!/bin/pyhton3
from sniffing.sniffing import sniffing
from reporting.generate import generate_report
from scanning.enumeration import scan_ip_range
from initialization.logger import MyLogger
from initialization.utilities import subnet_to_cidr
from rich.console import Console
from scanning.hue import discover_philips_hue_bridge
import asyncio
from app.app import IoTective
from datetime import datetime


async def main(config: dict):
    logger = MyLogger(__name__)
    console = Console()
    now = datetime.now()

    report = {
        "file_name": now.strftime("report_%Y-%m-%d_%H-%M-%S.json"),
        "start_time": str(now),
        "end_time": "",
        "config": config,
        "network_scan": [],
        "hue_bridge": [],
        "sniffing": {
            "wifi": {},
            "bluetooth": {},
            "zigbee": {}
        }
    }

    logger.info("Starting IoTective scanner...")
    # Phase 2: Scanning
    if config["network_scanning"]:
        if config != {} and config["ip_address"] != "":
            # nmap scanning
            ip_range = f"{config['ip_address']}/{subnet_to_cidr(config['netmask'])}"
            report["network_scan"] = scan_ip_range(target=ip_range, logger=logger, console=console, config=report["config"])

            # Identify Philips Hue bridges on the network
            report["hue_bridge"] = discover_philips_hue_bridge(logger=logger, console=console)
        else:
            logger.error("Failed to determine target IP range")
    # Phase 3: Sniffing
    report["sniffing"] = await sniffing(config=config, logger=logger, console=console)
    generate_report(report=report)
    return


if __name__ == "__main__":
    try:
        # Phase 1: Initialization
        interface = IoTective()
        configuration = interface.run()
        interface.exit()

        if configuration is not None:
            asyncio.run(main(config=configuration))
            interface.run()
    except KeyboardInterrupt:
        raise SystemExit("\nCtrl+C pressed. Exiting.")
