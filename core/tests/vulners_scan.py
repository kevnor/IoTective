from nmap3 import Nmap
import json

nmp = Nmap()
arguments = "--open -T4 -O --script vulners"
results = nmp.nmap_version_detection(target="10.0.0.171", args=arguments)
print(json.dumps(results, indent=4))
