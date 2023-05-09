from .utilities import create_report_file
from datetime import datetime


def generate_report(report: dict) -> None:
    report_path = create_report_file(filename=report["file_name"])
    report["end_time"] = str(datetime.now())
    print(report)
