import asyncio

import pyrcrack


async def capture_packets():
    airmon = pyrcrack.AirmonNg()
    interfaces = await airmon.interfaces
    print(str(interfaces))
    print(str([a.asdict() for a in interfaces]))

    async with airmon("wlan0") as mon:
        async with pyrcrack.AirmonNg() as pdump:
            async for aps in pdump(mon.monitor_interface):
                print(aps)
                break


asyncio.run(capture_packets())
