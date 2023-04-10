import subprocess


def check_wireless_mode():
    # Run the iwconfig command and capture the output
    output = subprocess.check_output(['iwconfig'])

    # Convert the output to a string and split it into lines
    output = output.decode('utf-8')
    lines = output.split('\n')

    # Search for the wireless mode in the output
    for line in lines:
        if 'Mode:' in line:
            mode = line.split('Mode:')[1].split()[0]
            return mode
    else:
        print("Wireless mode not found")
        return None


print(check_wireless_mode())
