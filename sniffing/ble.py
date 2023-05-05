#!/usr/bin/env python3
from .utilities import format_bluetooth_details
from bleak import BleakScanner, BleakClient, BleakError
from rich.progress import track


async def bluetooth_enumeration(logger):
    devices = await scan_devices(logger, timeout=1)
    print(devices)

    bluetooth_data = {}

    for address in track(devices, description="Processing Bluetooth devices..."):
        try:
            data = format_bluetooth_details(raw_details=devices[address], logger=logger)
            data["services"] = await get_device_services(address=address, logger=logger)
            bluetooth_data[address] = data
        except:
            continue
    logger.info(f"Managed to gather information about {str(len(bluetooth_data))} ble devices.")
    return bluetooth_data


async def get_device_services(address: str, logger, timeout=20):
    try:
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
    except BleakError as e:
        logger.error(e)


async def scan_devices(logger, timeout=5):
    try:
        logger.info(f"Scanning for Bluetooth LE devices for {str(timeout)} seconds...")
        return await BleakScanner.discover(timeout=timeout, return_adv=True)
    except BleakError as e:
        logger.error(e)
