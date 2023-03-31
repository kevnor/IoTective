#!/bin/pyhton3
import argparse
from core.utils.configure import configure
from core.modules.scanning import device_enumeration


def main():
    parser = argparse.ArgumentParser(
        prog="IoTective",
        description="Internet of Things automated security scanning and penetration testing tool."
    )

    parser.add_argument(
        "-c",
        "--configure",
        help="start configuration wizard",
        required=False,
        action="store_true"
    )

    parser.add_argument(
        "--run",
        required=False,
        action="store_true",
        help="run the scanner"
    )

    args = parser.parse_args()

    if args.configure:
        if args.run:
            print("The scanner will run after configuration.")
        configure()

    if args.run:
        device_enumeration()


if __name__ == '__main__':
    main()
