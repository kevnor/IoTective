import os

def get_wifi_ssid():
    ssid = os.popen("sudo iwgetid -r").read()

    if not ssid:
        print("Could not determine SSID of connected Wi-Fi router. Are you sure you are connect over Wi-Fi?")

        while True:
            answer = input("Enter SSID manually? (Y/n)")
            if answer.upper() == "Y" or answer == "":
                ssid = input("SSID (the name of your Wi-Fi network): ")
                break
            elif answer.upper() == "N":
                return False
    return ssid


print(get_wifi_ssid())
