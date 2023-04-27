import json
import os
import datetime
from core.utils.formatting import create_scan_file_path


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

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

    return data, path
