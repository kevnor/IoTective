from textual.reactive import reactive
from textual.screen import Screen
import os
import json
from datetime import datetime

from textual.app import ComposeResult
from textual.widgets import DataTable, Button
from textual.containers import Vertical
from textual.widgets import MarkdownViewer, Markdown

COLUMNS = ("Time", "Nmap Scanning", "Bluetooth", "Wi-Fi", "ZigBee")


class Reports(Screen):
    markdown = reactive(f"""# Scan Information""")

    def compose(self) -> ComposeResult:
        with Vertical(id="left_pane"):
            yield Button("Back", id="back")
        with Vertical(id="right_pane"):
            yield DataTable(id="reports_table")
            yield MarkdownViewer(markdown=self.markdown, show_table_of_contents=True)

    def on_mount(self) -> None:
        self.query_one(MarkdownViewer).display = False

        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns(*COLUMNS)
        for report in get_reports_list():
            table.add_row(
                datetime.strptime(report["end_time"], '%Y-%m-%d %H:%M:%S.%f').strftime('%A, %B %d, %Y %I:%M:%S %p'),
                "✅" if report["config"]["network_scanning"] else "❌",
                "✅" if report["config"]["ble_scanning"] else "❌",
                "✅" if report["config"]["wifi_sniffing"] else "❌",
                "✅" if report["config"]["zigbee_sniffing"] else "❌",
                key=report["file_name"]
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            if self.query_one(DataTable).display:
                self.app.pop_screen()
            else:
                self.query_one(MarkdownViewer).display = False
                self.query_one(DataTable).display = True

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        file_name = str(event.row_key.value)
        reports_directory = os.path.join(os.getcwd(), 'reports')
        filepath = os.path.join(reports_directory, file_name)
        with open(filepath, 'r') as report:
            data = json.load(report)
            self.markdown = create_report_information_markdown(data)
        self.query_one(Markdown).update(markdown=create_report_information_markdown(data=data))
        self.query_one(DataTable).display = False
        self.query_one(MarkdownViewer).display = True


def get_reports_list() -> list[dict]:
    reports_directory = os.path.join(os.getcwd(), 'reports')
    parsed_data = []
    for filename in os.listdir(reports_directory):
        if filename.endswith('.json'):
            filepath = os.path.join(reports_directory, filename)
            with open(filepath, 'r') as f:
                try:
                    data = json.load(f)
                    parsed_data.append({
                        "file_name": data["file_name"],
                        "start_time": data["start_time"],
                        "end_time": data["end_time"],
                        "config": data["config"]
                    })
                except json.JSONDecodeError:
                    print(f"Error decoding JSON data in file {filename}")
    return parsed_data


def create_report_information_markdown(data: dict[str, any]) -> str:
    markdown = f"""
# Scan Information

**Start Time:** {datetime.strptime(data['start_time'], '%Y-%m-%d %H:%M:%S.%f').strftime('%A, %B %d, %Y %I:%M:%S %p')}

**End Time:** {datetime.strptime(data['end_time'], '%Y-%m-%d %H:%M:%S.%f').strftime('%A, %B %d, %Y %I:%M:%S %p')}

## Configuration

**Interface:** {data['config']['interface']}

**IP Address:** {data['config']['ip_address']}

**Netmask:** {data['config']['netmask']}

**Network Scanning:** {'Yes' if data['config']['network_scanning'] else 'No'}

**WiFi Sniffing:** {'Yes' if data['config']['wifi_sniffing'] else 'No'}

**BLE Scanning:** {'Yes' if data['config']['ble_scanning'] else 'No'}

**Zigbee Sniffing:** {'Yes' if data['config']['zigbee_sniffing'] else 'No'}

**Zigbee Device Path:** {data['config']['zigbee_device_path']}


## Scan Summary

Network devices: {len(data["network_scan"])}

Wi-Fi devices: {len(data["sniffing"]["wifi"])}

Bluetooth devices: {len(data["sniffing"]["bluetooth"])}

ZigBee devices: {len(data["sniffing"]["zigbee"])}


"""
    if data['config']['zigbee_sniffing']:
        markdown += create_zigbee_markdown(data=data["sniffing"]["zigbee"])
    if data['config']['network_scanning']:
        markdown += create_network_scanning_markdown(data=data["network_scan"])
        if len(data["hue_bridge"]) > 0:
            markdown += create_hue_bridge_markdown(data=data["hue_bridge"])

    return markdown


def create_hue_bridge_markdown(data: list[dict]) -> str:
    markdown = f"""
    
### Philips Hue Bridge

"""
    for bridge in data:
        markdown += f"""\
    
| Name              | Value  |
| ----------------- | ------ |
| `IP Address`          | `{bridge["ip"]}` |
| `MAC Address`  | `{bridge["mac"]}`  |
| `Name` | `{bridge["name"]}`  |
| `Bridge ID` | `{bridge["bridge_id"]}` |
| `Model ID`| `{bridge["model_id"]}`  |
| `API Version`   | `{bridge["api_version"]}` |
| `Software Version`   | `{bridge["software_version"]}` |
| `Port`   | `{bridge["port"]}` |
| `Server`   | `{bridge["server"]}` |
| `Type`   | `{bridge["type"]}` |
| `Weight`   | `{bridge["weight"]}` |
| `Cloud Connected`   | `{'Yes' if bridge["internet"] else 'No'}` |

"""
    return markdown


def create_network_scanning_markdown(data: list) -> str:
    formatted_devices = f"""
## Network Devices

"""

    for device in data:
        formatted_devices += f"""\

### {device["ip"]}

| Name              | Value  |
| ----------------- | ------ |
| `IP Address`          | `{device["ip"]}` |
| `MAC Address`  | `{device["mac"]}`  |
| `Vendor` | `{device["vendor"]}`  |
| `OS` | `{device["os"]}` |
| `OS Guess Accuracy`| `{device["os_accuracy"]}`  |
| `OS Type`   | `{device["os_type"]}` |


"""
        if device["ports"]:
            formatted_devices += f"""\

#### Ports ####

            """
            for port in device["ports"]:
                formatted_devices += f"""\

##### Port {port["port_id"]} #####

| Name              | Value  |
| ----------------- | ------ |
| `Port`          | `{port["port_id"]}` |
| `Protocol`  | `{port["protocol"]}`  |
| `Service Name` | `{port["service_name"]}`  |
| `Product` | `{port["product"]}` |
| `Version`| `{port["version"]}`  |
| `CPE`   | `{port["cpe"][0] if len(port["cpe"]) > 0 else "Unknown"}` |

"""
                if port["cves"] is not None:
                    formatted_devices += f"""\

** Potential Vulnerabilities **

"""
                    for cve in port["cves"]:
                        formatted_devices += f"""\

| Name              | Value  |
| ----------------- | ------ |
| `ID`          | `{cve["id"]}` |
| `Is exploit?`  | `{'Yes' if cve["is_exploit"] else 'No'}`  |
| `CVSS` | `{cve["cvss"]}`  |
| `Type` | `{cve["type"]}` |

"""

    return formatted_devices


def create_zigbee_markdown(data: list) -> str:
    formatted_devices = f"""
## ZigBee Devices

"""

    for channel in data:
        channel_markdown = f"""\
### Channel {channel}

"""

        for device in data[channel]:
            channel_markdown += f"""\
| Name              | Value  |
| ----------------- | ------ |
| `PAN ID`          | `{device["PanId"]}` |
| `Permit Joining`  | `{"Yes" if device["PermitJoining"] == 1 else "No"}`  |
| `Router Capacity` | `{device["PermitJoining"]}`  |
| `Device Capacity` | `{device["DeviceCapacity"]}` |
| `Protocol Version`| `{device["ProtocolVersion"]}`  |
| `Stack Profile`   | `{device["StackProfile"]}` |
| `LQI`             | `{device["LQI"]}` |   
| `Depth`   | `{device["Depth"]}` |   
| `Update ID`   | `{device["UpdateId"]}` |   


"""
        formatted_devices += channel_markdown

    return formatted_devices
