#!/usr/bin/env python3
from .utilities import format_bluetooth_details
from bleak import BleakScanner, BleakClient


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


async def get_device_services(address, timeout=20):
    this_device = await BleakScanner.find_device_by_address(address, timeout=timeout)
    async with BleakClient(this_device) as client:
        services = []
        for service in client.services:
            service_data = {
                "name": str(service),
                "description": str(service.description),
                "characteristics": {}
            }

            for c in service.characteristics:
                service_data["characteristics"][c.uuid] = {
                    "uuid": str(c.uuid),
                    "description": str(c.description),
                    "handle": c.handle,
                    "properties": c.properties,
                    "descriptors": []
                }
                for descriptor in c.descriptors:
                    service_data["characteristics"][c.uuid]["descriptors"].append(str(descriptor))
            services.append(service_data)
        return services


async def scan_devices(timeout=5):
    print(f"Scanning for Bluetooth LE devices for {str(timeout)} seconds...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    return devices
