#!/bin/pyhton3
from nmap import PortScanner
from core.host import get_default_gateway
from configparser import ConfigParser
from core.utility import subnet_to_cidr
from bleak import BleakScanner, BleakClient
import asyncio


def callback_result(host, scan_result):
    print('--------------')
    print(host, scan_result)


# Nmap is used to discover open ports and detect OS
def nmap_enumeration():
    nm = PortScanner()

    # Get network interface configuration
    config = ConfigParser()
    config.read("config.ini")
    nic = config["Network Interface"]
    ip_range = nic['ipv4'] + "/" + str(subnet_to_cidr(nic['netmask']))

    # Perform nmap scan on IP range of network interface
    print("Performing host discovery and port scanning on " + ip_range + "...")
    arguments = "-n -PE -PS80,3389,443 -PU40125,161 -PA21 --source-port 53 -v -T4 " + ip_range
    scan_results = nm.scan(arguments=arguments)
    output = {}
    default_gateway = get_default_gateway()

    # Extract useful information from the scan
    for host in scan_results['scan']:
        if host == '127.0.0.1' or host == default_gateway or "mac" not in scan_results['scan'][host]['addresses']:
            continue
        output[host] = {'addresses': scan_results['scan'][host]['addresses'], 'vendor': {}, 'ports': {}, 'os': {}}
        if 'vendor' in scan_results['scan'][host] and scan_results['scan'][host]['vendor']:
            output[host]['vendor'] = scan_results['scan'][host]['vendor'][output[host]['addresses']['mac']]
        if 'tcp' in scan_results['scan'][host] and scan_results['scan'][host]['tcp']:
            output[host]['ports'] = scan_results['scan'][host]['tcp']
        if 'osmatch' in scan_results['scan'][host] and scan_results['scan'][host]['osmatch']:
            output[host]['os'] = scan_results['scan'][host]['osmatch']
    return output


async def bluetooth_enumeration():
    print("Discovering Bluetooth devices...")
    devices = await BleakScanner.discover()
    bluetooth_data = {}

    for device in devices:
        try:
            this_device = await BleakScanner.find_device_by_address(device.address)
            async with BleakClient(this_device) as client:
                print(f'Services found for device')
                print(f'\tDevice address:{device.address}')
                print(f'\tDevice name:{device.name}')

                print('\tServices:')
                for service in client.services:
                    print()
                    print(f'\t\tDescription: {service.description}')
                    print(f'\t\tService: {service}')

                    print('\t\tCharacteristics:')
                    for c in service.characteristics:
                        print()
                        print(f'\t\t\tUUID: {c.uuid}'),
                        print(f'\t\t\tDescription: {c.description}')
                        print(f'\t\t\tHandle: {c.handle}'),
                        print(f'\t\t\tProperties: {c.properties}')

                        print('\t\tDescriptors:')
                        for descrip in c.descriptors:
                            print(descrip)
        except:
            print("Could not connect to device: " + str(device))

asyncio.run(bluetooth_enumeration())
