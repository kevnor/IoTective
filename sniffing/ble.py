#!/usr/bin/env python3
from .utilities import format_bluetooth_details
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakDeviceNotFoundError, BleakError, BleakDBusError
from rich.progress import Progress


async def bluetooth_enumeration(logger) -> dict[str, dict]:
    devices = await scan_devices(logger)

    if len(devices) > 0:
        with Progress() as scanner:
            scan_task = scanner.add_task(description="Fetching device services...", total=len(devices))
            for address in devices:
                try:
                    scanner.update(scan_task, description=f"Fetching services for device {address}...")
                    devices[address]["services"] = await get_device_services(address=address, logger=logger)
                    scanner.advance(scan_task, advance=1)
                except BleakError as e:
                    logger.error(e)
                    scanner.advance(scan_task, advance=1)
                    devices[address]["services"] = []
        logger.info(f"Gathered information about {str(len(devices))} Bluetooth devices.")
        return devices
    else:
        return {}


async def get_device_services(address: str, logger) -> list[dict]:
    try:
        this_device = await BleakScanner.find_device_by_address(device_identifier=address, timeout=5)
        if this_device is not None:
            async with BleakClient(this_device.address, timeout=5) as client:
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
        return []
    except BleakDeviceNotFoundError as e:
        logger.info(e)
        return []
    except BleakDBusError as e:
        logger.error(e)
        return []
    except TimeoutError as e:
        logger.info(f"Connection to {address} timed out")
        return []


async def scan_devices(logger, timeout=5) -> dict[str, dict]:
    try:
        logger.info(f"Scanning for Bluetooth LE devices for {str(timeout)} seconds...")

        devices = await BleakScanner.discover(timeout=timeout, return_adv=True)

        formatted_devices = {}

        for device in devices:
            formatted_devices[device] = format_bluetooth_details(raw_details=devices[device], logger=logger)

        return formatted_devices
    except BleakDBusError as e:
        logger.error(e)
        return {}



