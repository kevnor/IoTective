import os
from configparser import ConfigParser
from core.modules.user import choose_nic, choose_ssid
from core.modules.output import print_scan_type_config, print_nic_config
from core.utils.sniffer import get_wifi_ssid, get_wireless_interfaces
from core.modules.output import print_wireless_interfaces
import asyncio
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text


def configure():
    """Main configuration function"""
    config, config_file = get_config()
    console = Console()
    console.clear()
    #
    # # Scan Types configuration
    # print_scan_type_config()
    # change_scan_type = Prompt.ask("Change configuration?", choices=["y", "n"], default="n")
    #
    # if change_scan_type == "n":
    #     console.clear()
    # else:
    #     configure_scan_types()
    #
    # # Network interface configuration
    # if config.getboolean("Scan Types", "ip_network"):
    #     print_nic_config()
    #     change_nic_config = Prompt.ask("Change configuration?", choices=["y", "n"], default="n")
    #     console.clear()
    #
    #     if change_nic_config == "y":
    #         configure_network_interface()

    # Wi-Fi sniffing configuration
    if config.getboolean("Scan Types", "wifi_sniffing"):
        configure_sniffer()

    console.print("Finished configuration")


def get_config():
    """Get configuration and configuration file"""
    config_file = os.path.join(os.path.dirname(__file__), "../../config.ini")
    config = ConfigParser()
    config.read(config_file)
    return config, config_file


def configure_scan_types():
    """Configure scan types"""
    config, config_file = get_config()
    console = Console()

    for key, value in config.items("Scan Types"):
        console.clear()
        print_scan_type_config()
        enable = Prompt.ask(f"Enable {key}?", choices=["y", "n"], default="y")
        if enable == "y":
            config.set("Scan Types", key, "True")
        else:
            config.set("Scan Types", key, "False")

        with open(config_file, "w") as configfile:
            config.write(configfile)
    console.clear()
    print_scan_type_config()


def configure_network_interface():
    """Configure network interface for IP scanning"""
    config, config_file = get_config()

    nic = choose_nic()
    config.set("Network Interface", "name", nic["name"])
    config.set("Network Interface", "ipv4", nic["IPv4"]["address"])
    config.set("Network Interface", "netmask", nic["IPv4"]["netmask"])
    config.set("Network Interface", "mac", nic["MAC"]["address"])
    with open(config_file, "w") as configfile:
        config.write(configfile)


def configure_sniffer():
    """Configure packet sniffer"""
    config, config_file = get_config()

    # Get wireless interfaces and print them to the user
    interfaces = asyncio.run(get_wireless_interfaces())
    printed = print_wireless_interfaces(interfaces=interfaces)

    if printed:
        choices = [str(index + 1) for index, item in enumerate(interfaces)]
        chosen_nic = Prompt.ask("Choose a wireless adapter for Wi-Fi sniffing: ", choices=choices)
        interface_name = interfaces[int(chosen_nic) - 1]["interface"]

        config.set("Sniffer Settings", "name", interface_name)
        with open(config_file, "w") as configfile:
            config.write(configfile)

        result = asyncio.run(get_wifi_ssid(interface_name))
        chosen_network = choose_ssid(result)

