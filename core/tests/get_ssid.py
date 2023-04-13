import os

def get_wifi_ssid():
    ssid = os.popen("sudo iwgetid -r").read()

    if not ssid:
        print("Could not determine SSID of connected Wi-Fi router. Are you sure you are connect over Wi-Fi?")
        answer = input("Enter SSID manually? (Y/n)")
        if answer.upper() == "Y" or answer == "":
            ssid = input("SSID (the name of your Wi-Fi network): ")

    return ssid


print(get_wifi_ssid())
