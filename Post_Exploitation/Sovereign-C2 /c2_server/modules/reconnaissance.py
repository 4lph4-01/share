import subprocess

def network_scan():
    command = 'nmap -sP 192.168.1.0/24'  # Adjust the network range as needed
    result = subprocess.check_output(command, shell=True).decode()
    return result

def execute(*args):
    return network_scan()

if __name__ == "__main__":
    print(network_scan())
