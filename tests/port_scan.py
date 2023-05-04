from nmap3 import Nmap


def port_scan(target):
    # log.logger("info", f"Scanning {target} for open ports ...")
    try:
        nmp = Nmap()
        return nmp.nmap_version_detection(target=target, args="-sS --host-timeout 240 -O -T4 --open")
    except Exception as e:
        raise SystemExit(f"Error: {e}")

