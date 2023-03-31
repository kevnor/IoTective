from nmap import PortScanner


def upnp_discovery(ip_range):
    nm = PortScanner()
    print("Performing UPnP discovery...")
    arguments = "-sU -p 1900 --script=upnp-info " + ip_range
    # arguments = "-sU -p 1900 --script=broadcast-upnp-info " + ip_range
    scan_results = nm.scan(arguments=arguments)
