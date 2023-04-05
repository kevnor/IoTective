#!/usr/bin/env python3
from core.protocols.ble.discovery import scan_devices
from core.protocols.ble.device import get_device_services
from core.utils.formatting import format_bluetooth_details
import asyncio


class TextColor:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    GOLD = '\033[33m'
    BOLD = '\033[1m'
    END = '\033[0m'


async def bluetooth_enumeration():
    devices = await scan_devices(timeout=1)

    bluetooth_data = {}
    count = 0

    for dev in devices:
        count += 1
        print(str(count) + "/" + str(len(devices)))

        try:
            data = format_bluetooth_details(devices[dev])
            data["services"] = await get_device_services(dev)
            print(data)
            bluetooth_data[dev] = data
        except:
            continue
    print("Managed to gather information about " + str(len(bluetooth_data)) + " ble devices.")
    return bluetooth_data

