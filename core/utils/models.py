from dataclasses import dataclass


@dataclass()
class Host:
    ip: str = "Unknown"
    mac: str = "Unknown"
    vendor: str = "Unknown"
    os: str = "Unknown"
    os_accuracy: int = 0
    os_type: str = "Unknown"
    ports: list = None

    def __str__(self):
        return (
                f"IP Address: {self.ip}"
                + f" MAC Address : {self.mac}"
                + f" Vendor : {self.vendor}\n"
                + f"OS : {self.os}"
                + f" Accuracy : {self.os_accuracy}"
                + f" Type : {self.os_type}"
                + "\n"
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
