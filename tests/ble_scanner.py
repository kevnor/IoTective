from bleak import BleakScanner, BleakClient
from bleak.exc import BleakDBusError, BleakDeviceNotFoundError, BleakError
import asyncio


async def get_device_services(address: str) -> list[dict]:
    try:
        this_device = await BleakScanner.find_device_by_address(device_identifier=address)
        print(f"This device: {this_device}")
        if this_device is not None:
            async with BleakClient(this_device.address) as client:
                print(f"Client: {client}")
                services = []
                for service in client.services:
                    print(f"Service: {service}")
                    service_data = {
                        "name": str(service),
                        "description": str(service.description),
                        "characteristics": {}
                    }
                    print(f"Len char: {len(service.characteristics)}")

                    for c in service.characteristics:
                        service_data["characteristics"][c.uuid] = {
                            "uuid": str(c.uuid),
                            "description": str(c.description),
                            "handle": c.handle,
                            "properties": c.properties,
                            "descriptors": []
                        }
                        print(f"Len desc: {len(c.descriptors)}")
                        for descriptor in c.descriptors:
                            service_data["characteristics"][c.uuid]["descriptors"].append(str(descriptor))
                    services.append(service_data)
                return services
        return []
    except BleakDeviceNotFoundError as e:
        print(e)
        return []
    except BleakDBusError as e:
        print(e)
        return []
    except BleakError as e:
        print(e)
        return []
    except TimeoutError as e:
        print(e)
        return []


ADDRESS = "BC:7E:8B:DD:4F:49"
print(asyncio.run(get_device_services(address=ADDRESS)))
