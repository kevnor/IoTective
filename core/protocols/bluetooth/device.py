from bleak import BleakScanner, BleakClient


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
