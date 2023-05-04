from prettytable import PrettyTable
import pyrcrack
import asyncio


def print_wireless_interfaces(interfaces):
    table = PrettyTable()
    table.field_names = ["", "PHY", "Interface", "Driver", "Chipset"]
    count = 0
    for interface in interfaces:
        count += 1
        table.add_row([count, interface["phy"], interface["interface"], interface["driver"], interface["chipset"]])
    print(table)


async def get_wireless_interfaces():
    airmon = pyrcrack.AirmonNg()
    interfaces = await airmon.interfaces
    interfaces_dict = []
    for interface in interfaces:
        interfaces_dict.append(interface.asdict())

    print_wireless_interfaces(interfaces=interfaces_dict)

asyncio.run(get_wireless_interfaces())
