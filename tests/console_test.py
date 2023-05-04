from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from datetime import datetime
from time import sleep
from rich.live import Live
import logging

content = "conent"
panel = Panel(content)
layout = Layout(panel)

with Live(layout, refresh_per_second=10, screen=True) as live:
    while True:
        sleep(0.1)
        content = live.console.out()
        live.console.print("Test")

