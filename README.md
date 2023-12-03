# IoTective

This script is to be used for security scanning of home environments that has connected smart home gadgets. The sript allows the user to run a scanning such as port scanning, Wi-Fi sniffing, ZigBee sniffing, and Bluetooth scanning. The result is a report of discovered devices and detected vulnerabilites (CVEs).

## Usage

1. Clone this repository:

```bash
git clone https://github.com/kevnor/IoTective.git
```

2. (Optional) Use a virtual environment:

```bash
python -m venv .venv
.venv/Scripts/Activate # Windows
```

2. Download dependencies:

```bash
cd iotective
python -m pip install -r requirements.txt
```

3. Start IoTective:

```bash
python iotective.py
```

4. Use the GUI to start scans and view reports.