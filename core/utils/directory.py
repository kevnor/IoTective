import os


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
