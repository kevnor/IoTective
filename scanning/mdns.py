# Ref: https://github.com/expliot-framework/expliot/blob/master/expliot/core/protocols/internet/mdns/__init__.py
import time
import socket
from zeroconf import Zeroconf, ServiceBrowser

from .service_types import MDNS_SERVICE_TYPES

DEFAULT_MDNS_TIMEOUT = 3.0


class MdnsListener:
    def __init__(self):
        self.data = []

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info is not None:
            self.data.append(info)

    def get_data(self) -> list:
        return self.data


class MdnsScan:
    """Discover local mDNS devices and services"""

    def __init__(self, service_type, timeout=DEFAULT_MDNS_TIMEOUT):
        self._service_type = MDNS_SERVICE_TYPES[service_type]
        self.devices = []
        self.timeout = timeout

    def get_devices(self) -> list:
        return self.devices

    def scan(self) -> None:
        zeroconf = Zeroconf()
        listener = MdnsListener()
        ServiceBrowser(zeroconf, self._service_type, listener)
        time.sleep(self.timeout)
        for info in listener.get_data():
            data = {
                "name": info.name,
                "type": info.type,
                "address": str(socket.inet_ntoa(info.addresses[0])),
                "port": info.port,
                "weight": info.weight,
                "priority": info.priority,
                "server": info.server,
                "properties": info.properties,
            }
            self.devices.append(data)
        zeroconf.close()
