from bleak import BleakScanner


async def scan_devices(timeout=5):
    print(f"Scanning for Bluetooth LE devices for {str(timeout)} seconds...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    return devices


