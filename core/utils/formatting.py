import os
import time
import json
import re


def format_bluetooth_details(raw_details):
    # Format device details into string. Accommodate errors caused by lack of data.
    dict_ = {
        # Device data:
        'address': None,
        'details': None,
        'name': None,

        # Advertisement data:
        'local_name': None,
        'manufacturer_data': None,
        'platform_data': None,
        'rssi': None,
        'service_data': None,
        'service_uuids': None,
        'tx_power': None
    }

    device_data = raw_details[0]
    advertisement_data = raw_details[1]

    try:
        dict_['address'] = device_data.address
    except Exception:
        print(f'Address not found for device with the following data: {device_data.address}')
    try:
        dict_['details'] = device_data.details
    except Exception:
        print(f'Details not found for device with the following data: {device_data.address}')
    try:
        dict_['name'] = device_data.name
    except Exception:
        print(f'Name not found for device with the following data: {device_data.address}')
    try:
        dict_['rssi'] = advertisement_data.rssi
    except Exception:
        print(f'RSSI not found for device with the following data: {device_data.address}')
    try:
        dict_['local_name'] = advertisement_data.local_name
    except Exception:
        print(f'Local name not found for device with the following data: {device_data.address}')
    try:
        dict_['manufacturer_data'] = advertisement_data.manufacturer_data
    except Exception:
        print(f'Manufacturer data not found for device with the following data: {device_data.address}')
    try:
        dict_['platform_data'] = advertisement_data.platform_data
    except Exception:
        print(f'Platform data not found for device with the following data: {device_data.address}')
    try:
        dict_['service_data'] = advertisement_data.service_data
    except Exception:
        print(f'Service data not found for device with the following data: {device_data.address}')
    try:
        dict_['service_uuids'] = advertisement_data.manufacturer_data
    except Exception:
        print(f'Service UUIDs not found for device with the following data: {device_data.address}')
    try:
        dict_['tx_power'] = advertisement_data.manufacturer_data
    except Exception:
        print(f'Tx Power data not found for device with the following data: {device_data.address}')
    return dict_


def subnet_to_cidr(subnet_mask):
    """
    Converts a subnet mask to CIDR notation.

    Args:
    subnet_mask (str): Subnet mask in dotted decimal notation (e.g. "255.255.255.0")

    Returns:
    int: CIDR notation (e.g. 24 for subnet mask "255.255.255.0")
    """
    # Validate the input
    parts = subnet_mask.split('.')
    if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        raise ValueError("Invalid subnet mask")

    # Convert subnet mask to binary string
    binary_mask = ''.join([bin(int(x))[2:].zfill(8) for x in subnet_mask.split('.')])

    # Count the number of consecutive ones in the binary string
    cidr = 0
    for i in range(len(binary_mask)):
        if binary_mask[i] == '1':
            cidr += 1
        else:
            break

    return cidr



def create_scan_file_path():
    # Create path and name for JSON file
    scans_dir = os.path.join(os.getcwd(), 'scans')
    os.makedirs(scans_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"scan_{timestamp}.json"
    path = os.path.join(scans_dir, filename)
    return path


DEFAULT_LOCAL_IP = "127.0.0.1"


def parse_scan_results(scan_results):
    parsed_results = {}
    for host, data in scan_results.items():
        mac_address = data.get("macaddress")
        if host == DEFAULT_LOCAL_IP or not mac_address:
            continue
        parsed_results[host] = {
            "addresses": {
                "mac": mac_address,
                "ipv4": host
            },
            "vendor": data["macaddress"].get("vendor", {}),
            "ports": data.get("ports", {}),
            "os": data.get("osmatch", {})
        }
    return parsed_results


def format_vulns_scan(ports):
    print(json.dumps(ports, indent=4, sort_keys=True))
    port_cves = {}

    for port, data in ports.items():
        try:
            vulners_script = data['script']['vulners']
            cve_matches = re.findall(r'\t+(CVE-\d+-\d+)\t+(\d+\.\d+)\t+([^\t]+)', vulners_script)
            formatted_cves = [{'name': cve[0], 'score': cve[1], 'url': f'https://vulners.com/cve/{cve[0]}'} for cve
                              in cve_matches]
            port_cves[port] = formatted_cves
        except KeyError:
            pass

    return port_cves

