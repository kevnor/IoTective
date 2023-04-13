import os
from configparser import ConfigParser
from core.modules.user import choose_nic
from core.modules.output import print_scan_type_config, print_nic_config
from core.utils.host import get_wireless_mode


def configure():
    config_file = os.path.join(os.path.dirname(__file__), "../../config.ini")
    config = ConfigParser()
    config.read(config_file)

    # Configure scan types
    print("Current scan types configuration:")
    print_scan_type_config()
    change_scan_types = input("Change scan types? (y/N)")
    if change_scan_types.upper() == "Y":
        scan_types_config = {
            "ip_network": input("Scan IP network? (Y/n)"),
            "wifi_sniffing": input("Perform Wi-Fi sniffing?"),
            "ble": input("Scan for BLE devices? (Y/n)"),
            "zigbee": input("Scan for ZigBee devices? (Y/n)")
        }
        for s_type in scan_types_config:
            if scan_types_config[s_type].upper() in ["Y", ""]:
                config.set("Scan Types", s_type, "True")
            elif scan_types_config[s_type].upper() == "N":
                config.set("Scan Types", s_type, "False")
        with open(config_file, "w") as configfile:
            config.write(configfile)
        print("Updated scan types configuration:")
        print_scan_type_config()

    # Configure network interface for IP scanning
    print("Current network interface configuration:")
    print_nic_config()
    answer = input("Change configuration? (y/N)")
    if answer.upper() == "Y":
        nic = choose_nic()
        config.set("Network Interface", "name", nic["name"])
        config.set("Network Interface", "ipv4", nic["IPv4"]["address"])
        config.set("Network Interface", "netmask", nic["IPv4"]["netmask"])
        config.set("Network Interface", "mac", nic["MAC"]["address"])
        with open(config_file, "w") as configfile:
            config.write(configfile)
        print("Updated network interface configuration:")
        print_nic_config()

    # If Wi-Fi sniffing is enabled, ensure that adapter is in 'monitor' mode
    if config.getboolean("Scan Types", "wifi_sniffing"):
        # Configure wireless adapter mode
        if get_wireless_mode() != "Monitor":
            print("WARNING: To perform packet sniffing, the network adapter needs to be in 'Monitoring' mode.")
            while True:
                answer = input("Change adapter setting to 'Monitoring' mode? (This will restart the adapter) (n/Y)")

                # Change wireless mode to "monitoring"
                if answer.upper() == "Y" or answer == "":
                    nic_name = config.get("Network Interface", "name")
                    os.system(f"sudo ifconfig {nic_name} down")
                    os.system(f"sudo iwconfig {nic_name} mode monitor")
                    os.system(f"sudo ifconfig {nic_name} up")

                    if get_wireless_mode() == "Monitoring":
                        print(f"{nic_name} is not in monitor mode")
                    else:
                        print(f"Failed to put {nic_name} into monitor mode")
                    break
                elif answer.upper() == "N":
                    print("Packet sniffing will not be performed")
                    config.set("Scan Types", "wifi_sniffing", "False")

    print("Finished configuration.")
