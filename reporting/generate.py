from .utilities import create_report_file
from datetime import datetime
import json


def generate_report(report: dict) -> None:
    report_path = create_report_file(filename=report["file_name"])
    report["end_time"] = str(datetime.now())

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=4)
