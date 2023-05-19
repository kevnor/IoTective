from .utilities import create_report_file
from datetime import datetime
import json


def generate_report(report: dict) -> None:
    if report["config"]["network_scanning"] and report["config"]["wifi_sniffing"]:
        report = update_wifi_information(report=report)

    report_path = create_report_file(filename=report["file_name"])
    report["end_time"] = str(datetime.now())

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=4)


def update_wifi_information(report: dict) -> dict:
    wifi_info = report["sniffing"]["wifi"]
    network_scan = report["network_scan"]

    for host in network_scan:
        mac = host["mac"].casefold()
        for bssid, mac_addresses in wifi_info.items():
            if mac in map(str.casefold, mac_addresses):
                host["bssid"] = bssid

    return report

