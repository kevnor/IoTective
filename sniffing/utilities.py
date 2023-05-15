import yaml
from bleak.uuids import normalize_uuid_str


def format_bluetooth_details(raw_details: list, logger) -> dict[str, any]:
    # Format device details into string. Accommodate errors caused by lack of data.
    dict_ = {
        # Device data:
        'address': None,
        'details': None,
        'name': None,

        # Advertisement data:
        'local_name': None,
        'company_name': None,
        'platform_data': None,
        'rssi': None,
        'service_data': None,
        'service_uuids': None,
        'tx_power': None
    }

    with open('sniffing/bt_company_identifiers.yaml', 'r') as file:
        identifiers = yaml.safe_load(file)

    device_data = raw_details[0]
    advertisement_data = raw_details[1]

    try:
        dict_['address'] = device_data.address
    except Exception:
        logger.error(f'Address not found for device with the following data: {device_data.address}')
    try:
        dict_['name'] = device_data.name
    except Exception:
        logger.error(f'Name not found for device with the following data: {device_data.address}')
    try:
        dict_['rssi'] = advertisement_data.rssi
    except Exception:
        logger.error(f'RSSI not found for device with the following data: {device_data.address}')
    try:
        dict_['local_name'] = advertisement_data.local_name
    except Exception:
        logger.error(f'Local name not found for device with the following data: {device_data.address}')
    try:
        names = []
        for key in advertisement_data.manufacturer_data:
            names.append(get_company_name(key, identifiers=identifiers['company_identifiers']))
        dict_['company_name'] = names
    except Exception:
        logger.error(f'Could not find company name for device with the following data: {device_data.address}')
    try:
        dict_['service_data'] = {}
        for data in advertisement_data.service_data:
            dict_['service_data'][data] = str(advertisement_data.service_data[data])
    except Exception:
        logger.error(f'Service data not found for device with the following data: {device_data.address}')
    try:
        dict_['service_uuids'] = [normalize_uuid_str(uuids) for uuids in advertisement_data.service_uuids]
    except Exception:
        logger.error(f'Service UUIDs not found for device with the following data: {device_data.address}')
    try:
        dict_['tx_power'] = advertisement_data.tx_power
    except Exception:
        logger.error(f'Tx Power data not found for device with the following data: {device_data.address}')
    return dict_


def get_company_name(value: int, identifiers):
    for identifier in identifiers:
        if identifier['value'] == value:
            return identifier['name']
    return 'Unknown'
