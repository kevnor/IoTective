import subprocess


def set_wireless_mode(interface: str, new_mode: str = "Monitor") -> bool:
    check = subprocess.check_call(["sudo airmon-ng check kill"], shell=True)
    start = subprocess.check_call(["sudo airmon-ng start " + interface], shell=True)
    return True


set_wireless_mode(interface="wlan0")
