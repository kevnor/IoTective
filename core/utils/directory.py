import json
import os
from configparser import ConfigParser
import datetime

from core.utils.formatting import create_scan_file_path


def get_config():
    """Get configuration and configuration file"""
    config_file = os.path.join(os.path.dirname(__file__), "../../config.ini")
    config = ConfigParser()
    config.read(config_file)
    return config, config_file


def get_latest_scan_path():
    # set path to scans directory
    path = "../../../scans"

    # get the list of all files in the directory
    files = os.listdir(path)

    if not files:
        print("ERROR: No scan files were found.")
        print("Perform a scan before trying again.")
        return None

    files.sort()

    return path + "/" + files[-1]


def create_scan_file():
    path = create_scan_file_path()

    # Initial data for JSON scan file
    data = {
        "scan_start": str(datetime.datetime.now()),
        "scan_end": "",
        "hosts": {
            "ip_network": {},
            "ble": {},
            "zigbee": {}
        },
        "vulnerabilities": {}
    }

    with open(path, "w") as file:
        json.dump(data, file, indent=4)

    return data, path
