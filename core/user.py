from core.host import get_nics
from prettytable import PrettyTable


def choose_nic():
    nics = get_nics()

    if not nics:
        print("Could not find any network interfaces.")
        return

    while True:
        chosen_nic = input("Choose a network interface (1 - " + str(len(nics)) + "):")
        if chosen_nic.isdigit() and int(chosen_nic) in nics:
            print("You chose:")
            print("==================================")
            print(nics[int(chosen_nic)]["name"])
            print("==================================")
            while True:
                answer = input("Is this correct? (Y/n) ")
                if answer.upper() == "Y":
                    return nics[int(chosen_nic)]
                elif answer.upper() == "N":
                    break
            continue
        else:
            print("Provide a number between 1 and " + str(len(nics)) + ".")


def choose_targets(hosts):
    table = PrettyTable()
    table.field_names = ["", "IPv4", "MAC", "Vendor", "Open ports", "OS (predicted)"]
    addresses = []

    # Create table of hosts to display in command prompt:
    for host in hosts:
        ip = host
        mac = ""
        vendor = ""
        open_ports = ""
        os = ""
        if "mac" in hosts[host]["addresses"] and hosts[host]["addresses"]["mac"]:
            mac = str(hosts[host]["addresses"]["mac"])
        if "ports" in hosts[host] and hosts[host]["ports"]:
            ports = []
            for port in hosts[host]["ports"]:
                ports.append(port)
            open_ports = str(ports)
        if hosts[host]["vendor"]:
            vendor = hosts[host]["vendor"]
        if hosts[host]['os']:
            os = "(" + hosts[host]['os'][0]['accuracy'] + "%) - " + hosts[host]['os'][0]['name']
        table.add_row([len(addresses), ip, mac, vendor, open_ports, os])
        addresses.append(host)
    table.align = "l"
    print(table)

    # User chooses what hosts to target from the table:
    while True:
        chosen_targets = str(input('Choose targets (separate targets with ","): '))
        chosen_targets.replace(" ", "")
        chosen_targets.split(",")
        chosen_targets = [s for s in chosen_targets if s.isdigit()]
        new_hosts = {}
        if chosen_targets:
            print(chosen_targets)
            for target in chosen_targets:
                new_hosts[addresses[int(target)]] = hosts.get(addresses[int(target)])
            break
        print("Invalid input.")
    return new_hosts
