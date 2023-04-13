import subprocess


def check_wireless_mode():
    # Run the iwconfig command and capture the output
    completed_process = subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Check if there was an error running the command
    if completed_process.returncode != 0:
        print(f"Error running iwconfig: {completed_process.stderr.decode().strip()}")
        return None

    # Convert the output to a string and split it into lines
    output = completed_process.stdout.decode('utf-8')
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
