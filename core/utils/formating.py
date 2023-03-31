
def format_bluetooth_details(raw_details):
    # Format device details into string. Accommodate errors caused by lack of data.
    dict_ = {
        'address': None,
        'details': None,
        'metadata': None,
        'name': None,
        'rssi': None
    }
    try:
        dict_['address'] = raw_details.address
    except Exception:
        print(f'Address not found for device with the following data: {raw_details}')
    try:
        dict_['details'] = raw_details.details
    except Exception:
        print(f'Details not found for device with the following data: {raw_details}')
    try:
        dict_['metadata'] = raw_details.metadata
    except Exception:
        print(f'Metadata not found for device with the following data: {raw_details}')
    try:
        dict_['name'] = raw_details.name
    except Exception:
        print(f'Name not found for device with the following data: {raw_details}')
    try:
        dict_['rssi'] = raw_details.rssi
    except Exception:
        print(f'RSSI not found for device with the following data: {raw_details}')

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
