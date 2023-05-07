from .utilities import (
    get_ip_range,
    get_interface_for_ip_range,
    is_wireless_interface,
    choose_zigbee_device
)
import os
from typing import Dict
from rich.prompt import Confirm
import sys


def configure(logger, console) -> Dict[str, any]:
    init_data: Dict[str, any] = {
        "ip_range": "",
        "interface": "",
        "sniffing": {
            "wifi": False,
            "bluetooth": False,
            "zigbee": False
        },
        "zigbee_device_path": ""
    }

    # Check if script is run as superuser
    if os.getuid() != 0:
        sys.exit("You need to run the script as root!")

    # Configure target IP range and Wi-Fi sniffer
    init_data["ip_range"] = get_ip_range(logger=logger, console=console)
    if init_data["ip_range"] != "":
        init_data["interface"] = get_interface_for_ip_range(ip_range=init_data["ip_range"])

        if init_data["interface"] != "":
            is_wireless = is_wireless_interface(iface=init_data["interface"])
            if is_wireless:
                init_data["sniffing"]["wifi"] = Confirm.ask("Do you want to include Wi-Fi sniffing?", default=True)

    # Configure Bluetooth sniffer
    init_data["sniffing"]["bluetooth"] = Confirm.ask(f"\nDo you want to include Bluetooth sniffing?", default=True)

    # Configure ZigBee sniffer
    init_data["sniffing"]["zigbee"] = Confirm.ask(f"\nDo you want to include ZigBee sniffing?", default=True)
    if init_data["sniffing"]["zigbee"]:
        device_path = choose_zigbee_device(logger=logger, console=console)
        if device_path != "":
            init_data["zigbee_device_path"] = device_path
        else:
            init_data["sniffing"]["zigbee"] = False

    return init_data
