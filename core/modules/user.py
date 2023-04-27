from core.utils.host import get_usb_devices
from prettytable import PrettyTable


def choose_zigbee_device():
    usb_devices = get_usb_devices()
    table = PrettyTable()
    table.field_names = ["", "Device", "Tag", "ID"]

    if not usb_devices:
        print("Could not find any USB devices.")
        return

    count = -1
    for device in usb_devices:
        count += 1
        table.add_row([count, device['device'], device['tag'], device['id']])
    table.align = "l"
    print(table)

    while True:
        chosen_device = int(input('Choose device: '))
        if chosen_device:
            return usb_devices[chosen_device]
        print("Invalid input.")
