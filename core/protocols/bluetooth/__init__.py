#!/usr/bin/env python3
from core.protocols.bluetooth.discovery import scan_devices
from core.protocols.bluetooth.device import get_device_services
from core.utils.formating import format_bluetooth_details, subnet_to_cidr


class TextColor:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    GOLD = '\033[33m'
    BOLD = '\033[1m'
    END = '\033[0m'


async def bluetooth_enumeration():
    devices = scan_devices()

    bluetooth_data = {}
    count = 0

    for dev in devices:
        count += 1
        print(str(count) + "/" + str(len(devices)))

        try:
            device_dict = format_bluetooth_details(dev)
            devices_data = {
                "address": device_dict["address"],
                "name": device_dict["name"],
                "rssi": device_dict["rssi"],
                "services": get_device_services(device_dict["address"])
            }

            bluetooth_data[dev.address] = devices_data
        except:
            continue
    print("Managed to gather information about " + str(len(bluetooth_data)) + " bluetooth devices.")
    return bluetooth_data
