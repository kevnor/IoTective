from core.utils.host import get_interface_for_ip_range, is_wireless_interface, get_connected_wifi_network, set_wireless_mode
from core.actions.packet_capture import get_bssid_for_essid, get_hosts_on_bssid


async def sniff_wifi(ip_range: str, logger, console):
    try:
        interface = get_interface_for_ip_range(ip_range=ip_range)

        if interface and is_wireless_interface(interface):
            logger.info(f"Using interface '{interface}' for sniffing")
            wifi_int = get_connected_wifi_network(interface=interface)

            if wifi_int is not None:
                logger.info(f"Targeting Wi-Fi with ESSID: '{wifi_int['ESSID']}'")
                logger.info(f"Switching '{interface}' to monitoring mode...")
                switch_mode = set_wireless_mode(interface=interface)
                if switch_mode:
                    logger.info(f"Success!")
                    # Retrieve BSSIDs that use the ESSID
                    # Could be multiple BSSIDs since some APs use both 2.4GHz and 5GHz bands with the same ESSID
                    ap_bssids = get_bssid_for_essid(essid=wifi_int['ESSID'], logger=logger, interface=interface)

                    if len(ap_bssids) > 0:
                        hosts = {}
                        for bid in ap_bssids:
                            hosts[bid] = get_hosts_on_bssid(bssid=bid, logger=logger, interface=interface)
                        print(hosts)

                    clean_up_interface = set_wireless_mode(interface=interface, new_mode="Managed")

    except Exception as e:
        print(f"An error occurred: {e}")
