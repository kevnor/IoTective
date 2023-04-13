import asyncio
import os
import pyrcrack
from configparser import ConfigParser


async def capture_packets():
    config_file = os.path.join(os.path.dirname(__file__), "../../config.ini")
    config = ConfigParser()
    config.read(config_file)

    interface = config.get("Network Interface", "name")

    airmon = pyrcrack.AirmonNg()

    async with airmon(interface) as mon:
        async with pyrcrack.AirmonNg() as pdump:
            async for aps in pdump(mon.monitor_interface):
                print(aps)
                break


asyncio.run(capture_packets())
