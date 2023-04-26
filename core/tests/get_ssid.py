import logging
import asyncio
import pywifi


async def get_wifi_ssid(interface: str):
    logging.basicConfig(level=logging.WARNING)
    int_face = None

    wifi = pywifi.PyWiFi()

    for i in wifi.interfaces():
        if i.name() == interface:
            int_face = i

    if int_face:
        int_face.scan()
        await asyncio.sleep(5)

        profiles = filter(lambda p: p.ssid and not p.ssid.startswith("\x00\x00"), int_face.scan_results())

        return [{'ssid': profile.ssid, 'bssid': profile.bssid} for profile in profiles]
    else:
        return None


print(asyncio.run(get_wifi_ssid("wlan0")))
