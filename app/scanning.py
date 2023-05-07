from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import OptionList, Label, RadioSet, RadioButton, Static, Header, Input, Switch
from initialization.utilities import get_ip_ranges, subnet_to_cidr, is_wireless_interface
from textual.app import ComposeResult, RenderResult
from textual.widgets.option_list import Option, Separator
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive
from textual.messages import Message

from textual import events
from textual.app import App
from textual.widgets import RadioSet, Label


class DisplayInfo(Static):
    interface = reactive({})

    def set_interface(self, interface):
        self.interface = interface

    def watch_interface(self, interface: dict) -> None:
        if self.interface == {}:
            self.update("None selected")
        else:
            self.update(f"{interface['interface']}")


class Configure(Widget):
    ip_ranges = reactive([])
    is_wireless = reactive(False)
    wifi_sniffing = reactive(False)
    selected_interface = reactive(-1)

    class InterfaceChanged(Message):
        def __init__(self, index) -> None:
            super().__init__()
            self.index = index

    def compose(self) -> ComposeResult:
        self.ip_ranges = get_ip_ranges()
        with Vertical():
            yield Label("Choose network interface:")
            with RadioSet(id="interfaces"):
                for ran in self.ip_ranges:
                    yield RadioButton(f"{ran['interface']}: {ran['ip_address']}/{subnet_to_cidr(ran['netmask'])}",
                                      id=ran['interface'])
            yield DisplayInfo()
            yield Horizontal(
                Static("Enable Wi-Fi sniffing?"),
                Switch(value=False, disabled=self.is_wireless)
            )

    def watch_selected_interface(self, indx: int):
        if indx > 0:
            is_wireless = is_wireless_interface(iface=self.ip_ranges[indx])
            self.is_wireless = is_wireless

    def on_radio_set_changed(self, event: RadioSet.Changed):
        self.selected_interface = event.index
        display = self.query_one(DisplayInfo)
        interface = self.ip_ranges[int(event.index)]
        display.set_interface(interface)


class Scanning(Screen):

    def compose(self) -> ComposeResult:
        yield Configure()
