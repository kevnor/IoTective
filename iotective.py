#!/bin/pyhton3
from core.modules.configuration import configure
from core.modules.scanning import get_scan_type, scan_target
from core.utils.console import cli
from core.utils.logger import MyLogger
from core.utils.host import get_ip_range
from rich.console import Console
from core.vendors.hue import discover_philips_hue_bridge


def main():
    logger = MyLogger(__name__)
    console = Console()

    args = cli()

    if args.configure:
        configure()

    if args.run:
        logger.info("Initializing IoTective scanner...")

        # Perform nmap scans to discover hosts on the network and find open ports
        target = get_ip_range(logger=logger)
        scan_type = get_scan_type(args=args, logger=logger)
        hosts = scan_target(args, target, scan_type, logger=logger, console=console)

        # Identify Philips Hue bridges on the network
        hue_bridges = discover_philips_hue_bridge(logger=logger, console=console)

        # Capture packets to identify wireless hosts


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
