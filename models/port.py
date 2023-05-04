from dataclasses import dataclass
from typing import Optional


@dataclass()
class Port:
    protocol: str = "Unknown"
    port_id: str = "Unknown"
    service_name: str = "Unknown"
    product: str = "Unknown"
    version: str = "Unknown"
    cpe: Optional[list[str]] = None
    cves: Optional[list[str]] = None

    def __str__(self) -> str:
        return (
            f"Port ID : {self.port_id}\n"
            + f"Protocol : {self.protocol}\n"
            + f"Service Name : {self.service_name}\n"
            + f"Product : {self.product}\n"
            + f"Version : {self.version}\n"
            + f"CPE : {self.cpe}\n"
        )

    def add_cve(self, cve: str) -> None:
        if self.cves is None:
            self.cves = []
        self.cves.append(cve)

    @classmethod
    def from_dict(cls, port: dict) -> "Port":
        new_port = cls()
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
