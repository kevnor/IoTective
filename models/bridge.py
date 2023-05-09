import requests
from rich.table import Table
from rich.console import Console
from dataclasses import dataclass


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

    def as_dict(self) -> dict:
        return vars(self)

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
