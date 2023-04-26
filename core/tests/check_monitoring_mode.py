import re
import subprocess


def get_supported_modes(interface: str):
    iw_output = subprocess.check_output(["iw", "list", interface], text=True)
    modes_match = re.search(r"Supported interface modes:([\s\S]+?)\n\n", iw_output)
    if modes_match:
        modes_str = modes_match.group(1)
        modes = re.findall(r"\t\*(\S+)", modes_str)
        return modes
    else:
        return []


print(get_supported_modes(interface="wlan0"))
