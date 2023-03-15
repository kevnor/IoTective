from core.user import choose_nic
from core.utility import subnet_to_cidr
from configparser import ConfigParser
from prettytable import PrettyTable
import yaml


def configure():
    config = ConfigParser()

    config.read("config.ini")
    print("Current network interface settings:")
    table = PrettyTable()
    table.field_names = ["Field", "Value"]
    table.add_row(["Name: ", config["Network Interface"]["name"]])
    table.add_row(["IPv4: ", config["Network Interface"]["ipv4"]])
    table.add_row(["Netmask: ", config["Network Interface"]["netmask"]])
    table.add_row(["MAC: ", config["Network Interface"]["mac"]])
    table.align["Field"] = "r"
    table.align["Value"] = "l"
    print(table)

    answer = input("Keep configuration? (y/N)")

    if answer.upper() == "N":
        nic = choose_nic()
        config["Network Interface"]["name"] = nic["name"]
        config["Network Interface"]["ipv4"] = nic["IPv4"]["address"]
        config["Network Interface"]["netmask"] = nic["IPv4"]["netmask"]
        config["Network Interface"]["mac"] = nic["MAC"]["address"]
        with open("config.ini", "w") as configfile:
            config.write(configfile)

        # Configure the docker container to use the private network interface of the host
        with open("docker-compose.yml", "r") as file:
            docker_config = yaml.safe_load(file)

        with open("docker-compose.yml", "w") as file:
            subnet = nic["IPv4"]["address"] + "/" + str(subnet_to_cidr(nic["IPv4"]["netmask"]))
            docker_config["networks"]["mynetwork"]["ipam"]["config"][0]["subnet"] = subnet
            yaml.dump(docker_config, file)


configure()
