from core.utils.host import get_interface_for_ip_range, is_wireless_interface, get_connected_wifi_network, set_wireless_mode
from core.actions.packet_capture import get_hosts_on_bssid, discover_bssids_for_ssid, get_unique_hosts
from core.utils.models import Host
import asyncio
from rich.console import Console
from core.utils.logger import MyLogger

async def sniff_wifi(ip_range: str, logger, console) -> list[Host]:
    try:
        #interface = get_interface_for_ip_range(ip_range=ip_range)
        interface = "wlan0"

        if is_wireless_interface(interface):
            logger.info(f"Using interface '{interface}' for sniffing")
            wifi_int = get_connected_wifi_network(interface=interface)
            wifi_int = {"ESSID": "Girls Gone Wireless"}

            if wifi_int is not None:
                logger.info(f"Targeting Wi-Fi with ESSID: '{wifi_int['ESSID']}'")
                logger.info(f"Switching '{interface}' to monitoring mode...")
                #switch_mode = set_wireless_mode(interface=interface)
                switch_mode = True
                if switch_mode:
                    logger.info(f"Success!")
                    # Retrieve BSSIDs that use the ESSID
                    # Could be multiple BSSIDs since some APs use both 2.4GHz and 5GHz bands with the same ESSID
                    #ap_bssids = get_bssid_for_essid(essid=wifi_int['ESSID'], logger=logger, interface=interface)

                    ap_bssids = discover_bssids_for_ssid(interface=interface, ssid=wifi_int['ESSID'], logger=logger)
                    print(ap_bssids)
                    if len(ap_bssids) > 0:
                        hosts = {}
                        for bid in ap_bssids:
                            hosts[bid] = []
                            for channel in ap_bssids[bid]:
                                hosts[bid].append(get_unique_hosts(interface=interface, bssid=bid, channel=channel, logger=logger))
                        print(hosts)
                    else:
                        logger.error("Did not manage to capture BSSID(s) of AP")
                    #clean_up_interface = set_wireless_mode(interface=interface, new_mode="Managed")
                else:
                    logger.error("Could not switch to monitoring mode")
            else:
                logger.error("Could not determine Wi-Fi interface because adapter is not connected to an AP")
        else:
            logger.error("Chosen interface is not a wireless interface")

    except Exception as e:
        logger.error(e)



