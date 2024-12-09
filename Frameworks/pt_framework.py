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
import requests
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
    """
    print(f"{Fore.GREEN}{splash}{Style.RESET_ALL}")

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
    print(f"{Fore.GREEN}{methodology}{Style.RESET_ALL}")

# Reconnaissance & Information Gathering
def run_more_mass():
    subprocess.run(["python3", "more_mass.py"])

def dns_lookup():
    domain = input(f"{Fore.YELLOW}Enter Domain for DNS Lookup: {Style.RESET_ALL}")
    subprocess.run(f"dig {domain}", shell=True)

# Scanning & Enumeration Tools
def run_nmap():
    ip = input(f"{Fore.YELLOW}Enter Target IP for Nmap Scan: {Style.RESET_ALL}")
    scan_type = input(f"{Fore.YELLOW}Enter Scan Type (e.g. sS, sT, sU): {Style.RESET_ALL}")
    subprocess.run(f"nmap -{scan_type} {ip}", shell=True)

def run_nikto():
    ip = input(f"{Fore.YELLOW}Enter Target IP for Nikto Scan: {Style.RESET_ALL}")
    subprocess.run(f"nikto -h {ip}", shell=True)

# Gaining Access Tools
def metasploit_menu():
    print(f"{Fore.GREEN}Launching Metasploit Framework...{Style.RESET_ALL}")
    subprocess.run(["msfconsole"])

def veil_evasion():
    print(f"{Fore.GREEN}Launching Veil Evasion...{Style.RESET_ALL}")
    subprocess.run(["veil"])

# Main Menu
def main_menu():
    display_splash_screen()
    check_and_install_tools(['nmap', 'nikto', 'metasploit', 'veil', 'more_mass'])

    options = [
        "Penetration Testing Methodology",
        "Reconnaissance & Information Gathering",
        "Scanning & Enumeration",
        "Gaining Access Tools",
        "Exit"
    ]
    display_in_columns(options)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        display_methodology()
    elif choice == "2":
        reconnaissance_menu()
    elif choice == "3":
        scanning_menu()
    elif choice == "4":
        gaining_access_menu()
    elif choice == "5":
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit()
    else:
        print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        main_menu()

# Reconnaissance Menu
def reconnaissance_menu():
    print(f"\n{Fore.GREEN}Reconnaissance & Information Gathering:{Style.RESET_ALL}")
    options = [
        "Run More_Mass (OSINT)",
        "DNS Lookup",
        "Return to Main Menu"
    ]
    display_in_columns(options)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        run_more_mass()
    elif choice == "2":
        dns_lookup()
    elif choice == "3":
        main_menu()
    else:
        print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        reconnaissance_menu()

# Scanning Menu
def scanning_menu():
    print(f"\n{Fore.GREEN}Scanning & Enumeration Tools:{Style.RESET_ALL}")
    options = [
        "Run Nmap Scan",
        "Run Nikto Scan",
        "Return to Main Menu"
    ]
    display_in_columns(options)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        run_nmap()
    elif choice == "2":
        run_nikto()
    elif choice == "3":
        main_menu()
    else:
        print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        scanning_menu()

# Gaining Access Menu
def gaining_access_menu():
    print(f"\n{Fore.GREEN}Gaining Access Tools:{Style.RESET_ALL}")
    options = [
        "Metasploit Framework",
        "Veil Evasion",
        "Return to Main Menu"
    ]
    display_in_columns(options)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        metasploit_menu()
    elif choice == "2":
        veil_evasion()
    elif choice == "3":
        main_menu()
    else:
        print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        gaining_access_menu()

if __name__ == "__main__":
    main_menu()
