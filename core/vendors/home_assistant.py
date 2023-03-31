from requests import get
from configparser import ConfigParser


def send_api_request(action):
    config = ConfigParser()
    config.read("config.ini")
    token = config["Home Assistant"]["bearer_token"]
    address = config["Home Assistant"]["address"]

    url = f"http://{address}:8123/api/{action}"
    headers = {
        "Authorization": token,
        "content-type": "application/json",
    }

    response = get(url, headers=headers)
    print(response.text)
