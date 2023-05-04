from rich.table import Table
from rich.console import Console
from rich.prompt import Prompt
import psutil

net_if_addrs = psutil.net_if_addrs()
net_if_stats = psutil.net_if_stats()

table = Table(title="Available Network Interfaces")
table.add_column("Interface Name")
table.add_column("Status")
table.add_column("MTU")
# table.add_column("Address Families")
table.add_column("IP Addresses")

for interface, stats in net_if_stats.items():
    status = "Up" if stats.isup else "Down"
    mtu = str(stats.mtu)
    # families = ", ".join(stats.family)
    addresses = ""
    for addr in net_if_addrs.get(interface, []):
        if addr.family == psutil.AF_INET:
            addresses += f"{addr.address} ({addr.netmask})\n"
    table.add_row(interface, status, mtu, addresses)

console = Console()
console.print(table)

interface_names = [row[0] for row in table.rows[1:]]  # Skip the header row
interface = Prompt.ask("Enter the name of the interface to use:", choices=interface_names)

console.print(f"You selected interface: {interface}")

