import asyncio

import pyrcrack

from rich.console import Console
from rich.prompt import Prompt


async def scan_for_targets():
    """Scan for targets, return json."""
    console = Console()
    console.clear()
    airmon = pyrcrack.AirmonNg()

    interfaces = await airmon.interfaces
    interface = Prompt.ask(
        'Select an interface',
        choices=[a.asdict()["interface"] for a in interfaces])

    async with airmon(interface) as mon:
        async with pyrcrack.AirodumpNg() as pdump:
            async for result in pdump(mon.monitor_interface):
                console.clear()
                console.print(result.table)
                await asyncio.sleep(2)


asyncio.run(scan_for_targets())
