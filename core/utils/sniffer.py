import subprocess
import os
import pyrcrack
import asyncio
from rich.console import Console
import time
import pywifi
from pywifi import const
import logging

from core.utils.host import get_interface_name


async def get_wireless_interfaces():
    airmon = pyrcrack.AirmonNg()
    interfaces = await airmon.interfaces
    interfaces_dict = []
    for interface in interfaces:
        interfaces_dict.append(interface.asdict())
    return interfaces_dict


def get_wireless_mode(interface):
    # Run the iwconfig command and capture the output
    completed_process = subprocess.run(['iwconfig',  interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Check if there was an error running the command
    if completed_process.returncode != 0:
        print(f"Error running iwconfig {interface}: {completed_process.stderr.decode().strip()}")
        return None

    # Convert the output to a string and split it into lines
    output = completed_process.stdout.decode('utf-8')
    lines = output.split('\n')

    # Search for the wireless mode in the output
    for line in lines:
        if 'Mode:' in line:
            mode = line.split('Mode:')[1].split()[0]
            return mode
    else:
        print("Wireless mode not found")
        return None


def set_wireless_mode(new_mode="Monitor"):
    interface = get_interface_name()
    current_mode = get_wireless_mode(interface)

    if current_mode == new_mode:
        return True
    else:
        try:
            subprocess.check_call(["sudo", "ifconfig", interface, "down"])
            subprocess.check_call(["sudo", "iwconfig", interface, "mode", "monitor"])
            subprocess.check_call(["sudo", "ifconfig", interface, "up"])

            subprocess.check_call(["sudo", "iw", "dev", interface, "set", "type", new_mode])
            print(f"Wireless mode set to {new_mode}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error setting wireless mode: {e}")
            return False


async def get_wifi_ssid(interface):
    logging.basicConfig(level=logging.WARNING)
    wifi = pywifi.PyWiFi()

    int_face = None
    for i in wifi.interfaces():
        if i.name() == interface:
            int_face = i

    if int_face:
        int_face.scan()
        await asyncio.sleep(5)

        profiles = []
        for profile in int_face.scan_results():
            profiles.append({
                'ssid': profile.ssid,
                'bssid': profile.bssid
            })
        return profiles
    else:
        return None


