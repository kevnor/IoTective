from .utilities import (
    get_ip_range,
    get_interface_for_ip_range,
    is_wireless_interface,
    check_monitor_mode_support
)
import os
from typing import Dict
from rich.prompt import Confirm
import sys


def configure(logger, console) -> Dict[str, any]:
    init_data: Dict[str, any] = {
        "is_root": False,
        "ip_range": "",
        "interface": "",
        "sniffing": {
            "wifi": False,
            "bluetooth": False,
            "zigbee": False
        }
    }

    # Check if script is run as superuser
    if os.getuid() != 0:
        sys.exit("You need to run the script as root!")

    init_data["ip_range"] = get_ip_range(logger=logger, console=console)
    if init_data["ip_range"] != "":
        init_data["interface"] = get_interface_for_ip_range(ip_range=init_data["ip_range"])

        if init_data["interface"] != "":
            supports_monitoring = check_monitor_mode_support(interface=init_data["interface"])
            is_wireless = is_wireless_interface(iface=init_data["interface"])
            if is_wireless and supports_monitoring:
                logger.info(f"Interface {init_data['interface']} can be used for Wi-Fi packet capture")
                init_data["sniffing"]["wifi"] = Confirm("Do you want to include Wi-Fi sniffing?")

    init_data["sniffing"]["bluetooth"] = Confirm("Do you want to include Bluetooth sniffing?")
    init_data["sniffing"]["zigbee"] = Confirm("Do you want to include ZigBee sniffing?")

    return init_data
