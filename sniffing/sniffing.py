from typing import Dict, Any
from .wifi import wifi_sniffing
from .ble import bluetooth_enumeration
from .zigbee import discover_zigbee_routers


async def sniffing(config: Dict, logger, console) -> Dict[str, Any]:
    hosts = {
        "wifi": {},
        "bluetooth": {},
        "zigbee": {}
    }

    try:
        if config["wifi_sniffing"]:
            hosts["wifi"] = await wifi_sniffing(interface=config["interface"], logger=logger, console=console)
        if config["ble_scanning"]:
            hosts["bluetooth"] = await bluetooth_enumeration(logger=logger)
        if config["zigbee_sniffing"]:
            hosts["zigbee"] = await discover_zigbee_routers(radio_path=config["zigbee_device_path"], logger=logger)
    except Exception as e:
        logger.error(e)
    print(hosts)
    return hosts
