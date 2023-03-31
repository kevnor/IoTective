from bleak import BleakScanner


async def scan_devices(timeout=5):
    print('Scanning for Bluetooth LE devices...')
    devices = await BleakScanner.discover(timeout=timeout)
    return devices
