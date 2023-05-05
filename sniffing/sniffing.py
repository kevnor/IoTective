from typing import Dict, Any
from .wifi import wifi_sniffing
from .ble import bluetooth_enumeration


async def sniffing(init_data: Dict, logger, console) -> Dict[str, Any]:
    try:
        hosts = {
            "wifi": {},
            "bluetooth": [],
            "zigbee": []
        }
        #if init_data["sniffing"]["wifi"]:
            #hosts["wifi"] = await wifi_sniffing(interface=init_data["interface"], logger=logger, console=console)
        if init_data["sniffing"]["bluetooth"]:
            hosts["bluetooth"] = await bluetooth_enumeration(logger)

        return hosts
    except Exception as e:
        logger.error(e)
