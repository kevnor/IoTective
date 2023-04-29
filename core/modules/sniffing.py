from typing import Dict, List, Any

from core.utils.host import get_connected_wifi_network, set_wireless_mode
from core.actions.packet_capture import discover_bssids_for_ssid, get_unique_hosts


async def sniffing(init_data: Dict, logger, console) -> Dict[str, List[Any]]:
    try:
        hosts = {
            "wifi": [],
            "bluetooth": [],
            "zigbee": []
        }
        if init_data["sniffing"]["wifi"]:
            hosts["wifi"] = await wifi_sniffing(interface=init_data["interface"], logger=logger, console=console)
        return hosts
    except Exception as e:
        logger.error(e)


async def wifi_sniffing(interface: str, logger, console) -> Dict[str, List]:
    # Get the name of the Wi-Fi network connected to the interface
    wifi_network = get_connected_wifi_network(interface=interface)

    if wifi_network is not None:
        # Retrieve BSSIDs that use the ESSID of the AP
        ap_bssids = discover_bssids_for_ssid(interface=interface, ssid=wifi_network['ESSID'], logger=logger)
        hosts = {}

        # Get MAC addresses of hosts connected to each BSSID
        if len(ap_bssids) > 0:
            for bid in ap_bssids:
                hosts[bid] = []
                for channel in ap_bssids[bid]:
                    hosts[bid].append(get_unique_hosts(interface=interface, bssid=bid, channel=channel, logger=logger))
        else:
            logger.error("Did not manage to capture BSSID(s) of AP")

        # clean_up_interface = set_wireless_mode(interface=interface, new_mode="Managed")
        return hosts
    else:
        logger.error("Could not switch to monitoring mode")
