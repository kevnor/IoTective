#!/usr/bin/env python3
from .utilities import format_bluetooth_details
from bleak import BleakScanner, BleakClient, BleakError
from rich.progress import Progress


async def bluetooth_enumeration(logger) -> dict[str, dict]:
    devices = await scan_devices(logger, timeout=10)

    if len(devices) > 0:
        with Progress() as scanner:
            scan_task = scanner.add_task(description="Fetching device services...", total=len(devices))
            for address in devices:
                try:
                    devices[address]["services"] = await get_device_services(address=address, logger=logger)
                    scanner.advance(scan_task, advance=1)
                except:
                    scanner.advance(scan_task, advance=1)
                    continue

        logger.info(f"Gathered information about {str(len(devices))} ble devices.")
        return devices
    else:
        return {}


async def get_device_services(address: str, logger, timeout=20) -> list[dict]:
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
        return []


async def scan_devices(logger, timeout=5) -> dict[str, dict]:
    try:
        logger.info(f"Scanning for Bluetooth LE devices for {str(timeout)} seconds...")

        devices = await BleakScanner.discover(timeout=timeout, return_adv=True)

        formatted_devices = {}

        for device in devices:
            formatted_devices[device] = format_bluetooth_details(raw_details=devices[device], logger=logger)

        return formatted_devices
    except BleakError as e:
        logger.error(e)
        return {}
