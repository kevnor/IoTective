import requests
from rich.table import Table
from rich.console import Console
from dataclasses import dataclass
from typing import Dict, Any


@dataclass()
class Bridge:
    ip: str
    mac: str = None
    name: str = None
    bridge_id: str = None
    model_id: str = None
    api_version: str = None
    software_version: str = None
    datastore_version: str = None
    port: int = None
    server: str = None
    type: str = None
    weight: int = None
    internet: bool = False
    cves: dict = None

    def print_config(self, console: Console):
        # Create a table to display the configuration
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Parameter", style="dim")
        table.add_column("Value")

        # Add rows to the table
        for attr_name in dir(self):
            if not attr_name.startswith("__") and not callable(getattr(self, attr_name)):
                attr_value = getattr(self, attr_name)
                table.add_row(attr_name, str(attr_value))

        # Print the table using Rich
        console.print(table)

    def update_bridge(self, data):
        self.name = data.get("name")
        self.type = data.get("type")
        self.port = data.get("port")
        self.weight = data.get("weight")
        self.server = data.get("server")
        properties = data.get("properties", {})
        self.bridge_id = properties.get(b'bridgeid', {}).decode("utf-8")
        self.model_id = properties.get(b'modelid', {}).decode("utf-8")
        self.mac = data.get("mac")

    def update_bridge_cloud(self, data):
        self.bridge_id = data.get("id")
        self.port = data.get("port")

    def get_config(self, logger):
        if self.ip:
            res = requests.get(f"https://{self.ip}/api/0/config", verify=False)
            if res.status_code == 200:
                data = res.json()
                logger.info("Successfully fetched bridge configuration.")
                self.name = data.get("name")
                self.datastore_version = data.get("datastoreversion")
                self.software_version = data.get("swversion")
                self.api_version = data.get("apiversion")
                self.bridge_id = data.get("bridgeid")
                self.mac = data.get("mac")
                self.model_id = data.get("modelid")
        else:
            logger.error("Can't fetch bridge configuration: Missing IP address.")

    def update_connectivity(self, connected):
        self.internet = connected

    def check_for_vulnerabilities(self):
        # Check if vulnerable to CVE-2020-6007 (Buffer Overflow)
        self.cves = {"CVE-2020-6007": self.api_version and self.api_version <= "1.31.0"}

        # Check if vulnerable to CVE-2017-14797 (Lack of Transport Encryption)
        self.cves = {"CVE-2017-14797": self.software_version and self.software_version < "1709131401"}


@dataclass()
class Host:
    ip: str = "Unknown"
    mac: str = "Unknown"
    vendor: str = "Unknown"
    os: str = "Unknown"
    os_accuracy: int = 0
    os_type: str = "Unknown"
    ports: list = None

    def __str__(self) -> str:
        return (
                f"IP Address: {self.ip}"
                + f" MAC Address : {self.mac}"
                + f" Vendor : {self.vendor}\n"
                + f"OS : {self.os}"
                + f" Accuracy : {self.os_accuracy}"
                + f" Type : {self.os_type}"
                + "\n"
        )

    def colored(self) -> str:
        return (
                f"[yellow]MAC Address :[/yellow] {self.mac}\n"
                + f"[yellow]Vendor :[/yellow] {self.vendor}\n"
                + f"[yellow]OS :[/yellow] {self.os}\n"
                + f"[yellow]Accuracy :[/yellow] {self.os_accuracy}\n"
                + f"[yellow]Type :[/yellow] {self.os_type[:20]}\n"
        )

    def add_port(self, port):
        if self.ports is None:
            self.ports = []
        self.ports.append(port)


@dataclass()
class Port:
    protocol: str = "Unknown"
    port_id: str = "Unknown"
    service_name: str = "Unknown"
    product: str = "Unknown"
    version: str = "Unknown"
    cpe: list = None
    cves: list = None

    def __str__(self):
        return (
                f"Port ID : {self.port_id}"
                + f"Protocol : {self.protocol}\n"
                + f" Service Name : {self.service_name}\n"
                + f"Product : {self.product}"
                + f" Version : {self.version}"
                + f" CPE : {self.cpe}"
                + "\n"
        )

    def add_cve(self, cve):
        if self.cves is None:
            self.cves = []
        self.cves.append(cve)


def update_host(host: Host, data: Dict[str, Any]) -> Host:
    if host.vendor == "Unknown":
        host.vendor = data.get("macaddress", {}).get("vendor", host.vendor)

    osmatch = data.get("osmatch", [{}])[0]
    if host.os == "Unknown":
        host.os = osmatch.get("name", "Unknown")
    if host.os_accuracy == 0:
        host.os_accuracy = osmatch.get("accuracy", "Unknown")
    if host.os_type == "Unknown":
        host.os_type = osmatch.get("osclass", {}).get("type", "Unknown")
    return host


def init_port(port: dict) -> Port:
    new_port = Port()
    new_port.protocol = port.get("protocol", "Unknown")
    new_port.port_id = port.get("portid", "Unknown")
    new_port.service_name = port.get("service", {}).get("name", "Unknown")
    new_port.product = port.get("service", {}).get("product", "Unknown")
    new_port.version = port.get("service", {}).get("version", "Unknown")
    new_port.cpe = [c.get("cpe", "Unknown") for c in port.get("cpe", [])]
    for script in port.get("scripts", []):
        if script and script["name"] == "vulners" and "data" in script:
            for cpe in script["data"]:
                if "children" in script["data"][cpe]:
                    for cve in script["data"][cpe]["children"]:
                        new_port.add_cve(cve)
    return new_port