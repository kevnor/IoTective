import requests
from .mdns import MdnsScan
from models.bridge import Bridge


def discover_philips_hue_bridge(logger, console) -> list[dict]:
    hue_scan = MdnsScan(service_type="hue")
    hue_scan.scan()
    discovered_bridges = hue_scan.get_devices()

    bridges = {}

    if not discovered_bridges:
        logger.warning("Could not find Philips Hue bridge using mDNS.")
    else:
        logger.info(f"Found {len(discovered_bridges)} Philips Hue bridge(s)")

        # Add bridges discovered by mDNS
        for bridge in discovered_bridges:
            new_bridge = Bridge(bridge["address"])
            new_bridge.update_bridge(data=bridge)
            bridges[new_bridge.ip] = new_bridge

    # Query Philips Hue bridge public endpoint
    # Rate limit: one request per 15 minutes per client
    try:
        res = requests.get("https://discovery.meethue.com")
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Could not fetch from Philips Hue endpoint discovery: {e}")
        return [bridges[bridge].as_dict() for bridge in bridges]

    if res.status_code == 200:
        # Updates connectivity status for each bridge discovered
        # If new bridge is discovered, create new Bridge object
        for bridge in res.json():
            internal_ip = bridge["internalipaddress"]
            if internal_ip in bridges:
                # Sets connectivity to True
                bridges[internal_ip].update_connectivity(connected=True)
            else:
                # If it's a previously undiscovered bridge, create new and add to bridges
                new_bridge = Bridge(internal_ip)
                new_bridge.update_bridge_cloud(data=bridge)
                new_bridge.update_connectivity(connected=True)
                bridges[new_bridge.ip] = new_bridge
    elif res.status_code == 429:
        logger.warning("Too many requests... Wait at least 15 minutes per request to https://discovery.meethue.com")
    else:
        logger.warning("Could not fetch from Philips Hue endpoint discovery")

    logger.info("Fetching bridge config...")
    for bridge in bridges.values():
        try:
            bridge.get_config(logger=logger)
            bridge.check_for_vulnerabilities()
        except requests.exceptions.RequestException as e:
            logger.error(f"Could not fetch config for bridge {bridge.ip}: {e}")
            continue
        bridge.print_config(console=console)

    return [bridges[bridge].as_dict() for bridge in bridges]
