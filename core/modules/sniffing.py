from core.utils.host import get_interface_for_ip_range, is_wireless_interface, get_wifi_network_name, set_wireless_mode
from core.actions.packet_capture import get_wifi_channels_for_essid


async def sniff_wifi(ip_range: str, logger, console):
    try:
        interface = get_interface_for_ip_range(ip_range=ip_range)

        if interface and is_wireless_interface(interface):
            logger.info(f"Using interface '{interface}' for sniffing")
            wifi_name = get_wifi_network_name(interface)

            if wifi_name is not None:
                logger.info(f"Targeting Wi-Fi with ESSID: '{wifi_name}'")
                logger.info(f"Switching '{interface}' to monitoring mode...")
                switch_mode = set_wireless_mode(interface=interface)
                if switch_mode:
                    logger.info(f"Success!")
                    channels = await get_wifi_channels_for_essid(essid=wifi_name, interface=interface)
                    print(channels)

                clean_up_interface = set_wireless_mode(interface=interface, new_mode="Managed")

    except Exception as e:
        print(f"An error occurred: {e}")
