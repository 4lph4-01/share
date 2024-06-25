###########################################################################################################################################################################################################
# Run using python3 wifitest.py: The script includes checking and installing necessary tools, setting the interface to monitor mode, 
# scanning for networks, capturing handshakes, and cracking the handshake using a wordlist.
# This script includes necessary error handling and guides users through the process with clear feedback. It provides an interactive menu for network scanning, handshake capturing, and password cracking, 
# making it more user-friendly and functional for real-world use.
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
import time

try:
    import scapy.all as scapy
except ImportError:
    print("Scapy is not installed. Installing Scapy...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    import scapy.all as scapy

def check_tool_installed(tool_name):
    try:
        subprocess.run([tool_name, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"{tool_name} is installed.")
    except subprocess.CalledProcessError:
        print(f"{tool_name} is not installed. Please install it and run the script again.")
        sys.exit(1)

def display_splash_screen():
    splash = r"""
__        _______ _     ____  _  __          _   _    _    _ _____ _     _____ ____  
\ \      / / ____| |   |  _ \| |/ /    /\   | \ | |  / \  | | ____| |   | ____|  _ \ 
 \ \ /\ / /|  _| | |   | |_) | ' /    /  \  |  \| | / _ \ | |  _| | |   |  _| | |_) |
  \ V  V / | |___| |___|  _ <|  <    / /\ \ | |\  |/ ___ \| | |___| |___| |___|  _ < 
   \_/\_/  |_____|_____|_| \_|_|\_\/_/    \_\_| \_/_/   \_\_|_____|_____|_____|_| \_\
"""
    print(splash)
    time.sleep(2)  # Display for 2 seconds

def set_monitor_mode(interface):
    try:
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        print(f"Interface {interface} set to monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting interface to monitor mode: {e}")

def scan_networks(interface):
    networks = {}
    def packet_handler(pkt):
        if pkt.haslayer(scapy.Dot11Beacon):
            bssid = pkt[scapy.Dot11].addr2
            ssid = pkt[scapy.Dot11Elt].info.decode()
            if bssid not in networks:
                networks[bssid] = ssid
                print(f"Found Network: BSSID: {bssid}, SSID: {ssid}")
    
    print("Scanning for networks. Press Ctrl+C to stop.")
    try:
        scapy.sniff(iface=interface, prn=packet_handler, timeout=30)
    except Exception as e:
        print(f"Error scanning networks: {e}")
    
    return networks

def capture_handshake(interface, bssid):
    print(f"Capturing handshake for BSSID: {bssid}")
    try:
        subprocess.run(["airodump-ng", "--bssid", bssid, "-w", "capture", interface], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error capturing handshake: {e}")

def crack_handshake(wordlist):
    print(f"Cracking handshake using wordlist: {wordlist}")
    try:
        subprocess.run(["aircrack-ng", "-w", wordlist, "capture-01.cap"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error cracking handshake: {e}")

def main():
    display_splash_screen()

    check_tool_installed("airodump-ng")
    check_tool_installed("aircrack-ng")

    bssid = None

    while True:
        print("\nWireless Penetration Test Tool")
        print("1. Set Interface to Monitor Mode")
        print("2. Scan for Networks and Get BSSID")
        print("3. Capture Handshake")
        print("4. Crack Handshake")
        print("5. Exit")
        
        choice = input("Select an option: ")

        if choice == '1':
            interface = input("Enter your wireless interface (e.g., wlan0): ")
            set_monitor_mode(interface)
        elif choice == '2':
            interface = input("Enter your wireless interface (e.g., wlan0): ")
            networks = scan_networks(interface)
            if networks:
                for i, (bssid, ssid) in enumerate(networks.items(), 1):
                    print(f"{i}. BSSID: {bssid}, SSID: {ssid}")
                selection = input("Select the network by number: ")
                try:
                    selection = int(selection) - 1
                    bssid = list(networks.keys())[selection]
                    print(f"Selected BSSID: {bssid}")
                except (ValueError, IndexError) as e:
                    print(f"Invalid selection: {e}")
            else:
                print("No networks found.")
        elif choice == '3':
            if bssid:
                interface = input("Enter your wireless interface (e.g., wlan0): ")
                capture_handshake(interface, bssid)
            else:
                print("You need to get the BSSID first. Select option 2.")
        elif choice == '4':
            wordlist = input("Enter the path to your wordlist: ")
            crack_handshake(wordlist)
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
