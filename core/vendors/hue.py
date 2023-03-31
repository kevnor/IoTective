import requests
from core.protocols.mdns import MdnsScan


class Bridge:
    def __init__(self, ip):
        self.ip = ip
        self.mac = None
        self.name = None
        self.bridge_id = None
        self.model_id = None
        self.api_version = None
        self.software_version = None
        self.datastore_version = None
        self.port = None
        self.server = None
        self.type = None
        self.weight = None
        self.internet = False
        self.cves = {
            "CVE-2020-6007": False,
            "CVE-2018-7580": False,
        }

    def update_bridge(self, data):
        if "name" in data and data["name"] is not None:
            self.name = data["name"]
        if "type" in data and data["type"] is not None:
            self.type = data["type"]
        if "port" in data and data["port"] is not None:
            self.port = data["port"]
        if "weight" in data and data["weight"] is not None:
            self.weight = data["weight"]
        if "server" in data and data["server"] is not None:
            self.server = data["server"]
        if "properties" in data and data["properties"] is not None:
            if b'bridgeid' in data["properties"] and data["properties"][b'bridgeid'] is not None:
                self.bridge_id = data["properties"][b'bridgeid'].decode("utf-8")
            if b'modelid' in data["properties"] and data["properties"][b'modelid'] is not None:
                self.model_id = data["properties"][b'modelid'].decode("utf-8")
        if "mac" in data and data["mac"]is not None:
            self.mac = data["mac"]

    def update_bridge_cloud(self, data):
        if "id" in data and data["id"] is not None:
            self.bridge_id = data["id"]
        if "port" in data and data["port"] is not None:
            self.port = data["port"]

    def get_config(self):
        if self.ip:
            res = requests.get(f"https://{self.ip}/api/0/config", verify=False)
            if res.status_code == 200:
                data = res.json()
                print("Successfully fetched bridge configuration.")
                self.name = data["name"]
                self.datastore_version = data["datastoreversion"]
                self.software_version = data["swversion"]
                self.api_version = data["apiversion"]
                self.bridge_id = data["bridgeid"]
                self.mac = data["mac"]
                self.model_id = data["modelid"]
        else:
            print("Can't fetch bridge configuration: Missing IP address.")

    def update_connectivity(self, connected):
        self.internet = connected

    def check_for_vulnerabilities(self):

        # Check if vulnerable to CVE-2020-6007 (Buffer Overflow)
        if self.api_version and self.api_version <= "1.31.0":
            self.cves["CVE-2020-6007"] = True
            print(f"Philips Hue bridge at {self.ip} is vulnerable to CVE-2020-6007. Please update!")
        else:
            print(f"Philips Hue bridge at {self.ip} is patched against CVE-2020-6007")

        # Check if vulnerable to CVE-2017-14797 (Lack of Transport Encryption)
        if self.software_version and self.software_version < "1709131401":
            self.cves["CVE-2017-14797"] = True
            print(f"Philips Hue bridge at {self.ip} is vulnerable to CVE-2017-14797. Please update!")
        else:
            print(f"Philips Hue bridge at {self.ip} is patched against CVE-2017-14797")


def discover_philips_hue_bridge():
    hue_scan = MdnsScan(service_type="hue")
    hue_scan.scan()
    discovered_bridges = hue_scan.get_devices()
    bridges = {}

    if not discovered_bridges:
        print("Could not find Philips Hue bridge using mDNS.")
    else:
        print(f"Found {len(discovered_bridges)} Philips Hue bridge(s)")

    # Add bridges discovered by mDNS
    for bridge in discovered_bridges:
        new_bridge = Bridge(bridge["address"])
        new_bridge.update_bridge(data=bridge)
        bridges[new_bridge.ip] = new_bridge

    # Query Philips Hue bridge public endpoint
    # Rate limit: one request per 15 minutes per client
    res = requests.get(f"https://discovery.meethue.com")

    if res.status_code == 200:
        # Updates connectivity status for each bridge discovered
        # If new bridge is discovered, create new Bridge object
        for bridge in res.json():
            internal_ip = bridge["internalipaddress"]
            if bridges[internal_ip]:
                # Sets connectivity to True
                bridges[internal_ip].update_connectivity(connected=True)
            else:
                # If it's a previously undiscovered bridge, create new and add to bridges
                new_bridge = Bridge(internal_ip)
                new_bridge.update_bridge_cloud(data=bridge)
                new_bridge.update_connectivity(connected=True)
                bridges[new_bridge.ip] = new_bridge
    elif res.status_code == 429:
        print("Too many requests... Wait at least 15 minutes pre request to https://discovery.meethue.com")
    else:
        print("Could not fetch from Philips Hue endpoint discovery")

    print("Fetching bridge config...")
    for bridge in bridges:
        bridges[bridge].get_config()
        bridges[bridge].check_for_vulnerabilities()

    return bridges
