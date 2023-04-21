#!/bin/pyhton3
from core.modules.configuration import configure
from core.modules.scanning import get_scan_type, get_scan_mode, scan
from core.utils.console import cli
from core.utils.logger import Logger
from core.utils.host import get_ip_range
from rich.console import Console


def main():
    console = Console(record=True)
    args = cli()
    log = Logger(console)

    if args.configure:
        configure()

    if args.run:
        target = get_ip_range()
        scan_type = get_scan_type(args=args, log=log)
        scan_mode = get_scan_mode(args=args, log=log)
        hosts = scan(args, target, scan_type, scan_mode, console, log)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
