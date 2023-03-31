from datetime import datetime
import subprocess
import time


def discover_zigbee_hosts():
    now = datetime.now()
    date_string = now.strftime("%Y-%m-%d-%H-%M-%S")
    timeout = 5

    for channel in range(15, 16):
        filename = "./zigbee_sniff_c{}_{}.pcap".format(channel, date_string)
        start_time = time.time()

        while (time.time() - start_time) < timeout:
            result = subprocess.run(
                ["sudo", "/opt/whsniff-1.3/whsniff", "-c", str(channel), ">", "/home/kali/" + filename])
            print(result)
