#!/bin/pyhton3

from core.scan_enum.enumeration import nmap_enumeration
import json
import os
import time
import datetime


def main():
    # Create path and name for JSON file
    timestr = time.strftime("%Y%m%d-%H%M%S")
    path = os.getcwd().split("/")
    path.append("scans")
    path.append("scan_" + timestr + ".json")
    path = "/".join(path)

    # Initial data for JSON scan file
    data = {
        "scan_start": str(datetime.datetime.now()),
        "scan_end": "",
        "hosts": {
            "ip_network": {},
            "bluetooth": {},
            "zigbee": {}
        }
    }

    # Create JSON file and insert initial data
    with open(path, "w") as file:
        json.dump(data, file)
        print("Created scan file at '" + path + "'")

    # Enumerate hosts on local network
    discovered_hosts = nmap_enumeration()

    # Insert information about hosts to JSON file
    with open(path, "r") as file:
        json_data = json.load(file)

    json_data["hosts"]["ip_network"] = discovered_hosts

    with open(path, "w") as file:
        json.dump(data, file)

    print("Finished scan.")

if __name__ == '__main__':
    main()
