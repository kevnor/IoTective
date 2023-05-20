from textual.screen import Screen
from initialization.utilities import get_ip_ranges, subnet_to_cidr
from textual.messages import Message
from typing import Dict, List, Any

from textual.app import ComposeResult
from textual.widgets import Label, RadioSet, RadioButton, Button, Switch
from textual.widget import Widget
from textual.reactive import reactive
from textual.containers import Vertical
import os


class ConfigurePane(Widget):
    configuration: Dict[str, Any] = reactive({
        "interface": "None Selected",
        "ip_address": "",
        "netmask": "",
        "network_scanning": False,
        "wifi_sniffing": False,
        "ble_scanning": False,
        "zigbee_sniffing": False,
        "zigbee_device_path": ""
    })
    ip_ranges: List[Dict[str, Any]] = reactive([])
    devices: List[str] = reactive([])

    def compose(self) -> ComposeResult:
        with Vertical(id="settings"):
            yield Label("Enable Network Scanning?:", classes="section")
            yield Switch(name="network_scanning", value=self.configuration["network_scanning"])
            yield Label("Enable Wi-Fi Sniffing?:", classes="section")
            yield Switch(name="wifi_sniffing", value=self.configuration["wifi_sniffing"])
            yield RadioSet(id="interfaces", disabled=True)
            yield Label("Enable Bluetooth Sniffing?:", classes="section")
            yield Switch(name="ble_scanning", value=self.configuration["ble_scanning"])
            yield Label("Enable ZigBee Sniffing?:", classes="section")
            yield Switch(name="zigbee_sniffing", id="zigbee_sniffing", value=self.configuration["zigbee_sniffing"])
            yield RadioSet(id="zigbee_devices", disabled=True)

    def on_mount(self):
        if "serial" in os.listdir("/dev/"):
            self.devices = os.listdir("/dev/serial/by-id/")
            for dev in self.devices:
                self.query_one("#zigbee_devices", RadioSet).mount(RadioButton(dev))
        if not self.devices:
            self.query_one("#zigbee_devices", RadioSet).visible = False
            self.query_one("#zigbee_sniffing", Switch).disabled = True

        try:
            self.ip_ranges = get_ip_ranges()
            if len(self.ip_ranges) < 1:
                self.query_one("#interfaces", RadioSet).visible = False
                self.query_one("#network_scanning", Switch).disabled = True
                self.query_one("#wifi_sniffing", Switch).disabled = True
            else:
                for range in self.ip_ranges:
                    self.query_one("#interfaces", RadioSet).mount(RadioButton(f"{range['interface']}: {range['ip_address']}/{subnet_to_cidr(range['netmask'])}"))
        except:
            self.query_one("#interfaces", RadioSet).visible = False
            self.query_one("#network_scanning", Switch).disabled = True
            self.query_one("#wifi_sniffing", Switch).disabled = True

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "interfaces":
            int_face = self.ip_ranges[event.index]
            self.configuration["interface"] = int_face["interface"]
            self.configuration["ip_address"] = int_face["ip_address"]
            self.configuration["netmask"] = int_face["netmask"]
        elif event.radio_set.id == "zigbee_devices":
            self.configuration["zigbee_device_path"] = f"/dev/serial/by-id/{self.devices[event.index]}"

    def on_switch_changed(self, event: Switch.Changed) -> None:
        self.configuration[event.switch.name] = event.switch.value
        if event.switch.name == "zigbee_sniffing":
            self.query_one("#zigbee_devices", RadioSet).disabled = not event.switch.value

        if not self.configuration["network_scanning"] and not self.configuration["wifi_sniffing"]:
            self.query_one("#interfaces", RadioSet).disabled = True
        else:
            self.query_one("#interfaces", RadioSet).disabled = False


class Scanning(Screen):
    class SubmitConfiguration(Message):
        def __init__(self, configuration: dict) -> None:
            super().__init__()
            self.configuration = configuration

    def compose(self) -> ComposeResult:
        with Vertical(id="left_pane"):
            yield Button("Start", id="start", variant="success")
            yield Button("Back", id="back")
        with Vertical(id="right_pane"):
            yield ConfigurePane()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "start":
            event.stop()
            self.post_message(self.SubmitConfiguration(self.query_one(ConfigurePane).configuration))
        elif event.button.id == "back":
            self.app.pop_screen()
