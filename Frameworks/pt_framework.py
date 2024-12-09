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
import shutil  # Added import
import requests
from pathlib import Path
from colorama import Fore, Style

# Splash Screen
def display_splash_screen():
    splash = """
   _____________________  ___________                                                  __                 _____  ____         .__       _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __            /  |  |/_   |______  |  |__   /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /  ______   /   |  |_|   |\____ \ |  |  \ /   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <  /_____/  /    ^   /|   ||  |_> >|   Y  |    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \          \____   | |___||   __/ |___|  |____   |           \_____  /___|
                 /_____/    \/                \/       \/     \/                        \/               |__|      |__|         \/     |__|                 \/     
    """
    print(f"{Fore.CYAN}{splash}{Style.RESET_ALL}")

# Check Tool Installation
def check_tool(tool_name):
    return shutil.which(tool_name) is not None

def install_tool(tool_name):
    print(f"{Fore.YELLOW}Installing {tool_name}...{Style.RESET_ALL}")
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

# Reconnaissance & Information Gathering
def reconnaissance():
    print(f"{Fore.CYAN}Reconnaissance & Information Gathering{Style.RESET_ALL}")
    options = [
        "Run more_mass.py (OSINT)",
        "Perform DNS Lookup",
        "Perform Shodan Search",
        "Back to Main Menu"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")
    
    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        more_mass_path = "/path/to/more_mass.py"  # Update with the actual path
        if os.path.exists(more_mass_path):
            subprocess.run(["python3", more_mass_path])
        else:
            print(f"{Fore.RED}more_mass.py not found!{Style.RESET_ALL}")
    elif choice == "2":
        domain = input("Enter domain for DNS Lookup: ")
        subprocess.run(["dig", domain])
    elif choice == "3":
        api_key = input("Enter your Shodan API Key: ")
        target = input("Enter target (IP or domain): ")
        response = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}")
        if response.status_code == 200:
            print(response.json())
        else:
            print(f"{Fore.RED}Error: {response.json().get('error', 'Unknown error')}{Style.RESET_ALL}")
    else:
        main_menu()

# Scanning & Enumeration
def scanning():
    print(f"{Fore.CYAN}Scanning & Enumeration{Style.RESET_ALL}")
    options = [
        "Run Nmap Scan",
        "Run Nikto Scan",
        "Back to Main Menu"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")

    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        target = input("Enter target for Nmap Scan: ")
        scan_type = input("Enter scan type (e.g., -sS, -sT, etc.): ")
        subprocess.run(["nmap", scan_type, target])
    elif choice == "2":
        target = input("Enter target for Nikto Scan: ")
        subprocess.run(["nikto", "-h", target])
    else:
        main_menu()

# Gaining Access Tools
def gaining_access():
    print(f"{Fore.CYAN}Gaining Access Tools{Style.RESET_ALL}")
    options = [
        "Launch Metasploit",
        "Launch SQLMap",
        "Launch Veil",
        "Back to Main Menu"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")

    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        subprocess.run(["msfconsole"])
    elif choice == "2":
        target = input("Enter target for SQLMap: ")
        subprocess.run(["sqlmap", "-u", target])
    elif choice == "3":
        veil_evasion()
    else:
        main_menu()

# Veil Evasion Integration
def veil_evasion():
    print(f"{Fore.GREEN}Launching Veil Evasion...{Style.RESET_ALL}")
    try:
        subprocess.run(["veil"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Veil encountered an error: {e}. Reconfiguring...{Style.RESET_ALL}")
        subprocess.run(["sudo", "/usr/share/veil/config/setup.sh", "--force", "--silent"], check=True)
        print(f"{Fore.YELLOW}Setup completed. Relaunching Veil...{Style.RESET_ALL}")
        subprocess.run(["veil"])

# Main Menu
def main_menu():
    display_splash_screen()
    tools = ['nmap', 'nikto', 'msfconsole', 'sqlmap', 'veil']
    check_and_install_tools(tools)

    options = [
        "PenTest Methodology",
        "Recon & Info Gathering",
        "Scanning & Enumeration",
        "Gaining Access",
        "Exit"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")

    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        print("Penetration Testing Methodology Overview:")
        print("""
        1. Reconnaissance & Information Gathering
        2. Scanning & Enumeration
        3. Gaining Access
        4. Setting Up Proxies
        5. Maintaining Access
        6. Covering Tracks
        7. Reporting
        """)
    elif choice == "2":
        reconnaissance()
    elif choice == "3":
        scanning()
    elif choice == "4":
        gaining_access()
    elif choice == "5":
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit()
    else:
        print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
        main_menu()

# Run the program
if __name__ == "__main__":
    main_menu()
