import json
import os
import datetime


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


def create_report_file(filename: str) -> str:
    reports_directory = os.path.join(os.getcwd(), 'reports')
    path = os.path.join(reports_directory, filename)

    with open(path, "w", encoding="utf-8") as file:
        json.dump({}, file, ensure_ascii=False, indent=4)

    return path


def create_scan_file_path():
    # Create path and name for JSON file
    scans_dir = os.path.join(os.getcwd(), 'scans')
    os.makedirs(scans_dir, exist_ok=True)
    timestamp = datetime.datetime.strftime("%Y%m%d-%H%M%S")
    filename = f"scan_{timestamp}.json"
    path = os.path.join(scans_dir, filename)
    return path
