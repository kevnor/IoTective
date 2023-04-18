import os
from configparser import ConfigParser


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
