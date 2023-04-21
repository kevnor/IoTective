from nmap3 import Nmap, NmapHostDiscovery
from core.utils.host import is_root


def port_scan(target):
    # log.logger("info", f"Scanning {target} for open ports ...")
    try:
        if is_root():
            nmp = Nmap()
            return nmp.nmap_version_detection(target=target, args="-sS --host-timeout 240 -O -T4 --open")
        else:
            nmp = NmapHostDiscovery()
            return nmp.nmap_portscan_only(target=target, args="--host-timeout 240 -T4 --open")
    except Exception as e:
        raise SystemExit(f"Error: {e}")


print(str(port_scan("10.0.0.171")))