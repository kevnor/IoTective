import pyrcrack
import asyncio


async def get_wifi_ssid(interface):
    airmon = pyrcrack.AirmonNg()

    async with airmon(interface) as mon:
        async with pyrcrack.AirodumpNg() as pdump:
            async for aps in pdump(mon.monitor_interface):
                print(aps.table)
                await asyncio.sleep(2)


asyncio.run(get_wifi_ssid("wlx54c9ff000d3b"))
