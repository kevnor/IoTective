from prettytable import PrettyTable
from core.utils.directory import get_latest_scan_path
import json
from configparser import ConfigParser


def display_bluetooth_devices():
    path = get_latest_scan_path()

    if not path:
        return

    with open(path, "r") as file:
        json_file = json.loads(file.read())
        bt_devices = json_file["hosts"]["ble"]

    table = PrettyTable()
    table.field_names = ["RSSI", "Address", "Name", "Services"]

    for device in bt_devices:
        dev = bt_devices[device]

        table.add_row([
            dev['rssi'],
            dev['address'],
            dev['name'],
            len(dev['services'])
        ])

    print(table)


def print_scan_type_config():
    config = ConfigParser()
    config.read("config.ini")

    scan_table = PrettyTable()
    scan_table.field_names = ["Scan Type", "Active"]
    scan_table.add_row(["IP Network", config.getboolean("Scan Types", "ip_network")])
    scan_table.add_row(["Bluetooth", config.getboolean("Scan Types", "ble")])
    scan_table.add_row(["ZigBee", config.getboolean("Scan Types", "zigbee")])
    scan_table.align = "l"
    print(scan_table)


def print_nic_config():
    config = ConfigParser()
    config.read("config.ini")

    table = PrettyTable()
    table.field_names = ["Field", "Value"]
    table.add_row(["Name: ", config["Network Interface"]["name"]])
    table.add_row(["IPv4: ", config["Network Interface"]["ipv4"]])
    table.add_row(["Netmask: ", config["Network Interface"]["netmask"]])
    table.add_row(["MAC: ", config["Network Interface"]["mac"]])
    table.align["Field"] = "r"
    table.align["Value"] = "l"
    print(table)
