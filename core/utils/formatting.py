import os
import time


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
    slash = os.path.sep
    timestr = time.strftime("%Y%m%d-%H%M%S")
    path = os.getcwd().split(slash)
    path.append("scans")
    path.append("scan_" + timestr + ".json")
    path = slash.join(path)
    return path


def format_discovered_ip_hosts(scan_results):
    output = {}
    # Extract useful information from the scan
    for host in scan_results["scan"]:
        if host in ["127.0.0.1"] or "mac" not in scan_results["scan"][host]["addresses"]:
            continue
        output[host] = {
            "addresses": scan_results["scan"][host]["addresses"],
            "vendor": {},
            "ports": {},
            "os": {}
        }
        if "vendor" in scan_results["scan"][host] and scan_results["scan"][host]["vendor"]:
            output[host]["vendor"] = scan_results["scan"][host]["vendor"][output[host]["addresses"]["mac"]]
        if "tcp" in scan_results["scan"][host] and scan_results["scan"][host]["tcp"]:
            output[host]["ports"] = scan_results["scan"][host]["tcp"]
        if "osmatch" in scan_results["scan"][host] and scan_results["scan"][host]["osmatch"]:
            output[host]["os"] = scan_results["scan"][host]["osmatch"]
    return output


def format_vulns_scan(ports):
    # Example output:
    # {
    #     22: [
    #         {
    #             "name": "CVE-2021-28041",
    #             "score": "4.6",
    #             "url": "https://vulners.com/cve/CVE-2021-28041",
    #         },
    #         {
    #             "name": "CVE-2021-41617",
    #             "score": "4.4",
    #             "url": "https://vulners.com/cve/CVE-2021-41617",
    #         }
    #     ],
    #     80: [
    #         {
    #             "name": "CVE-2022-22707",
    #             "score": "4.3",
    #             "url": "https://vulners.com/cve/CVE-2022-22707",
    #         }
    #     ],
    # }

    port_cves = {}

    for port in ports:
        if 'script' in ports[port] \
                and 'vulners' in ports['tcp'][port]['script']:
            formatted_cves = []
            output = ports[port]['script']['vulners']
            nl = "\n"
            output = output.split(''.join(nl))
            cves = output[2:]
            tab = '\t'
            for cve in cves:
                cve_data = cve.split(''.join(tab))
                formatted_cve = {
                    'name': cve_data[1],
                    'score': cve_data[2],
                    'url': cve_data[3]
                }
                formatted_cves.append(formatted_cve)
            port_cves[port] = formatted_cves
    return port_cves
