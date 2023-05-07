from typing import Dict, Any
from .wifi import wifi_sniffing
from .ble import bluetooth_enumeration
from .zigbee import discover_zigbee_routers


async def sniffing(init_data: Dict, logger, console) -> Dict[str, Any]:
    try:
        hosts = {
            "wifi": {},
            "bluetooth": [],
            "zigbee": []
        }
        #if init_data["sniffing"]["wifi"]:
            #hosts["wifi"] = await wifi_sniffing(interface=init_data["interface"], logger=logger, console=console)
        #if init_data["sniffing"]["bluetooth"]:
        #    hosts["bluetooth"] = await bluetooth_enumeration(logger)
        if init_data["sniffing"]["zigbee"]:
            hosts["zigbee"] = await discover_zigbee_routers(radio_path=init_data["zigbee_device_path"])

        return hosts
    except Exception as e:
        logger.error(e)
