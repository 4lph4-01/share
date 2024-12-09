######################################################################################################################################################################################################################
# Python script Penetration Testing & Ethical Hacking Framework, Note: Be mindful of the scope of work, & rules of engagement. Ensure more_mass.py is in the same working directory or absolutepath for integration. 
# sudo python3 pt_framework.py. Optional API's, and subdomain bruteforce. 
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
import requests
from pathlib import Path
from colorama import Fore, Style


def display_splash_screen():
    splash = r"""

_____________________  ___________                                                  __                  _____  ______________  ___ ___    _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___||____|    \___|_  /\____   |           \_____  /___|
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
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)

    """
    print(f"{Fore.CYAN}{splash}{Style.RESET_ALL}")


# Tool Installation Check
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


# Ensure More_Mass Script
def ensure_more_mass():
    current_dir = os.path.dirname(__file__)
    more_mass_source = "/path/to/more_mass.py"  # Replace with actual source path
    more_mass_dest = os.path.join(current_dir, "more_mass.py")

    if not os.path.exists(more_mass_dest):
        print(f"{Fore.YELLOW}Copying more_mass.py to {current_dir}...{Style.RESET_ALL}")
        try:
            shutil.copy(more_mass_source, more_mass_dest)
            print(f"{Fore.GREEN}more_mass.py successfully added.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Failed to copy more_mass.py: {e}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        print(f"{Fore.GREEN}more_mass.py is already present in {current_dir}.{Style.RESET_ALL}")


# Reconnaissance
def reconnaissance():
    print(f"{Fore.CYAN}Reconnaissance & Information Gathering{Style.RESET_ALL}")
    options = [
        "Run more_mass.py (OSINT)",
        "Perform DNS Lookup",
        "Perform WHOIS Lookup",
        "Perform Shodan Search",
        "Use The Harvester",
        "Use SpiderFoot",
        "Back to Main Menu"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")

    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        domain = input("Enter the domain to gather more information on: ")
        subprocess.run(["python3", "more_mass.py", domain])
    elif choice == "2":
        domain = input("Enter domain for DNS Lookup: ")
        subprocess.run(["dig", domain])
    elif choice == "3":
        target = input("Enter domain for WHOIS Lookup: ")
        subprocess.run(["whois", target])
    elif choice == "4":
        api_key = input("Enter your Shodan API Key: ")
        target = input("Enter target (IP or domain): ")
        response = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}")
        print(response.json() if response.status_code == 200 else f"Error: {response.json().get('error')}")
    elif choice == "5":
        domain = input("Enter domain for The Harvester: ")
        subprocess.run(["theharvester", "-d", domain, "-l", "500", "-b", "all"])
    elif choice == "6":
        target = input("Enter target for SpiderFoot: ")
        subprocess.run(["spiderfoot", "-s", target])
    else:
        main_menu()


# Scanning
def scanning():
    print(f"{Fore.CYAN}Scanning & Enumeration{Style.RESET_ALL}")
    options = [
        "Run Nmap Scan",
        "Run Nikto Scan",
        "Run Enum4Linux",
        "Run OpenVAS",
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
    elif choice == "3":
        target = input("Enter target for Enum4Linux: ")
        subprocess.run(["enum4linux", target])
    elif choice == "4":
        subprocess.run(["openvas-start"])
    else:
        main_menu()


# Main Menu
def main_menu():
    display_splash_screen()
    ensure_more_mass()
    tools = ['nmap', 'nikto', 'msfconsole', 'sqlmap', 'hydra', 'john', 'enum4linux', 'spiderfoot', 'theharvester', 'openvas']
    check_and_install_tools(tools)

    options = [
        "Reconnaissance & Information Gathering",
        "Scanning & Enumeration",
        "Gaining Access",
        "Maintaining Access",
        "Covering Tracks",
        "Generate Report",
        "Exit"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")

    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        reconnaissance()
    elif choice == "2":
        scanning()
    elif choice == "3":
        gaining_access()
    elif choice == "4":
        maintaining_access()
    elif choice == "5":
        covering_tracks()
    elif choice == "6":
        reporting()
    elif choice == "7":
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    else:
        main_menu()


if __name__ == "__main__":
    main_menu()
