from scapy.sendrecv import sniff, wrpcap
from core.utils.host import get_wireless_mode, set_wireless_mode
from configparser import ConfigParser
import os
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


capture_packets()
