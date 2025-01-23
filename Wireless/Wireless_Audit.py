########################################################################################################################################################################################
# A python srcipt for auditing wireless assets and connected devices. Be sure to change line 48 the wireless interface to that matching your own wlan name.. By 41ph4-01 23/04/2024 & our community. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################################

import subprocess

# Banner
def display_splash_screen():
    splash = r"""
 
    
__      __.__                 .__                                    _____            .___.__   __     ___________            .__                 _____  ____.____   __________  ___ ___    _____           _______  ____ 
/  \    /  \__|_______   ____  |  |    ____    ______  ______        /  _  \  __ __  __| _/|__|_/  |_   \__    ___/____   ____ |  |               /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
\   \/\/   /  |\_  __ \_/ __ \ |  |  _/ __ \  /  ___/ /  ___/       /  /_\  \|  |  \/ __ | |  |\   __\    |    |  /  _ \ /  _ \|  |     ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 \        /|  | |  | \/\  ___/ |  |__\  ___/  \___ \  \___ \       /    |    \  |  / /_/ | |  | |  |      |    | (  <_> |  <_> )  |__  /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
  \__/\  / |__| |__|    \___  >|____/ \___  >/____  >/____  >______\____|__  /____/\____ | |__| |__|______|____|  \____/ \____/|____/           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
       \/                   \/            \/      \/      \//_____/        \/           \/         /_____/                                           |__|             \/               \/      |__|                 \/

                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/      (_ _)
                                 /\      {====}     )___(        | |____....----....____         _
                      (\=,      //\\      )__(     /_____\       | |\                . .~~~~---~~ |
      __    |'-'-'|  //  .\    (    )    /____\     |   |        | | |         __\\ /(/(  .       |
     /  \   |_____| (( \_  \    )__(      |  |      |   |        | | |      <--= '|/_/_( /|       |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |        | | |       }\~) | / _(./      ..|
    /____\   |   |  (/     \    |  |      |  |      |   |        | | |.:::::::\\/      --...::::::|
     |  |    |   |   | _.-'|    |  |      |  |      |   |        | | |:::::::::\//::\\__\:::::::::|
     |__|    )___(    )___(    /____\    /____\    /_____\       | | |::::::::_//_:_//__\\_:::::::| 
    (====)  (=====)  (=====)  (======)  (======)  (=======)      | | |::::::::::::::::::::::::::::|
    }===={  }====={  }====={  }======{  }======{  }======={      | |/:::''''~~~~'''':::::::::::::'~
   (______)(_______)(_______)(________)(________)(_________)     | |
    
"""

    print(splash)
    print("Wireless Audit Tool - 41PH4-01 & Our Community\n")


# Function to discover wireless access points with encryption type and encryption level
def discover_access_points(interface):
    print("[+] Discovering Access Points...")
    access_points = []
    try:
        result = subprocess.check_output(["iwlist", interface, "scan"])
        result = result.decode("utf-8")
        ap_info = {}
        for line in result.split("\n"):
            if "ESSID:" in line:
                if ap_info:
                    access_points.append(ap_info)
                ap_info = {"ESSID": line.split('"')[1]}
            elif "Encryption key:" in line:
                if "off" in line:
                    ap_info["Encryption"] = "Open"
                else:
                    ap_info["Encryption"] = "Encrypted"
            elif "Pairwise Ciphers" in line:
                ap_info["Encryption Level"] = line.split(": ")[1].split(" ")[0]
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
    print("[+] Found Access Points:")
    for ap in access_points:
        print(f"  ESSID: {ap['ESSID']}, Encryption: {ap.get('Encryption', 'Unknown')}, Encryption Level: {ap.get('Encryption Level', 'Unknown')}")
    
    active_hosts = scan_network()
    print("[+] Found Active Hosts:", active_hosts)

if __name__ == "__main__":
    main()
