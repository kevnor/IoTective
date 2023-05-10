def format_bluetooth_details(raw_details, logger) -> dict[str, any]:
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
        logger.error(f'Address not found for device with the following data: {device_data.address}')
    try:
        dict_['details'] = device_data.details
    except Exception:
        logger.error(f'Details not found for device with the following data: {device_data.address}')
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
    #try:
    #    dict_['manufacturer_data'] = advertisement_data.manufacturer_data
    #except Exception:
    #    logger.error(f'Manufacturer data not found for device with the following data: {device_data.address}')
    try:
        dict_['platform_data'] = advertisement_data.platform_data
    except Exception:
        logger.error(f'Platform data not found for device with the following data: {device_data.address}')
    try:
        dict_['service_data'] = advertisement_data.service_data
    except Exception:
        logger.error(f'Service data not found for device with the following data: {device_data.address}')
    try:
        dict_['service_uuids'] = advertisement_data.manufacturer_data
    except Exception:
        logger.error(f'Service UUIDs not found for device with the following data: {device_data.address}')
    try:
        dict_['tx_power'] = advertisement_data.manufacturer_data
    except Exception:
        logger.error(f'Tx Power data not found for device with the following data: {device_data.address}')
    return dict_
