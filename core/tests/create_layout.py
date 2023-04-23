from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from datetime import datetime
from time import sleep
from rich.live import Live
from rich.logging import RichHandler
from logging import Logger, getLogger


class Header:
    """Display header with clock."""

    def __rich__(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(
            "[b]IoTective[/b] Network Scanner",
            datetime.now().ctime().replace(":", "[blink]:[/]"),
        )
        return Panel(grid, style="red")


def make_layout(handler: RichHandler) -> Layout:
    # Define the layout
    layout = Layout()

    # Add a banner to the top of the layout
    banner = Header()
    main_area = Layout(ratio=1)

    layout.split(
        Layout(banner, size=3),
        main_area
    )

    # Add the summary to the upper section of the right section
    summary_table = Table(title="Summary")
    summary_table.add_column("Network", justify="center")
    summary_table.add_column("Devices Found", justify="center")
    summary_table.add_row("My Network", "10")

    # Add the latest discovered host information to the lower section of the right section
    host_info = Panel("Latest Host Info", title="Host Info")

    # Add the console output to the left section
    console_output = Panel.fit(handler, title="Output")

    # Add the summary and host information to the right section
    right_section = Layout()
    right_section.split_column(
        Layout(summary_table),
        Layout(host_info)
    )

    # Add the main area, split horizontally into two sections
    main_area.split_row(
        Layout(console_output),
        right_section
    )

    return layout


log = getLogger()
handler = RichHandler(show_time=True)
log.addHandler(handler)

lay = make_layout(handler=handler)

with Live(lay, refresh_per_second=10, screen=True):
    while True:
        sleep(0.1)
        log.error("[bold red blink]Server is shutting down![/]", extra={"markup": True})

