#!/bin/pyhton3

from core.scan_enum.enumeration import nmap_enumeration
import json
import os


def main():
    path = os.getcwd().split("/")
    path.append("scans")
    path.append("scan.json")
    path = "/".join(path)

    discovered_hosts = nmap_enumeration()
    print(json.dumps(discovered_hosts, indent=4))

    with open(path, "w") as file:
        json.dump(discovered_hosts, file)
    # with open(path, 'r') as file:
    #     data = json.load(file)
    #     hosts = data["hosts"]
    #     if hosts:
    #         print(nmap_enumeration(hosts))
    # if discovered_hosts:
    #     chosen_targets = choose_targets()
    #     print(chosen_targets)
    # else:
    #     print("No hosts were found. Try another network interface.")


if __name__ == '__main__':
    main()
