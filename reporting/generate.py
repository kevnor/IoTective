from .utilities import create_report_file


def generate_report(report: dict) -> None:
    print(report)
    report_path = create_report_file(filename=report["file_name"])
