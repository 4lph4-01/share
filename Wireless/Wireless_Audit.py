import subprocess

# Function to discover wireless access points
def discover_access_points(interface):
    print("[+] Discovering Access Points...")
    access_points = []
    try:
        result = subprocess.check_output(["iwlist", interface, "scan"])
        result = result.decode("utf-8")
        for line in result.split("\n"):
            if "ESSID:" in line:
                ssid = line.split('"')[1]
                access_points.append(ssid)
    except subprocess.CalledProcessError:
        print("[-] Error: Failed to execute iwlist command.")
    return access_points

# Function to scan for active hosts
def scan_network():
    print("[+] Scanning Network...")
    active_hosts = []
    try:
        result = subprocess.check_output(["arp-scan", "-l"])
        result = result.decode("utf-8")
        for line in result.split("\n"):
            if len(line.strip()) > 0 and line[0].isdigit():
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip_address = parts[0]
                    active_hosts.append(ip_address)
    except subprocess.CalledProcessError:
        print("[-] Error: Failed to execute arp-scan command.")
    return active_hosts

# Main function
def main():
    wireless_interface = "wlan0"  # Change this to your wireless interface
    access_points = discover_access_points(wireless_interface)
    print("[+] Found Access Points:", access_points)
    
    active_hosts = scan_network()
    print("[+] Found Active Hosts:", active_hosts)

if __name__ == "__main__":
    main()