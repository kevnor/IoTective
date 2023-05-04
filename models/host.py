from dataclasses import dataclass
from typing import Any, Dict
from .port import Port


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

    def add_port(self, port: Port) -> None:
        if self.ports is None:
            self.ports = []
        self.ports.append(port)

    def update_host(self, data: Dict[str, Any]) -> None:
        if self.vendor == "Unknown":
            self.vendor = data.get("macaddress", {}).get("vendor", self.vendor)

        os_match = data.get("osmatch", [{}])[0]
        if self.os == "Unknown":
            self.os = os_match.get("name", "Unknown")
        if self.os_accuracy == 0:
            self.os_accuracy = os_match.get("accuracy", "Unknown")
        if self.os_type == "Unknown":
            self.os_type = os_match.get("osclass", {}).get("type", "Unknown")
