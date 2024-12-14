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


import sys
import os
import shutil
import subprocess
import requests
from pathlib import Path
from colorama import Fore, Style


def display_splash_screen():
    splash = r"""

 _____________________  ___________                                                  __                  _____  ____.____   __________  ___ ___    _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
                 /_____/    \/                \/       \/     \/                        \/                |__|             \/               \/      |__|                 \/     

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
    result = None  # Placeholder for captured output
    
    try:
        if choice == "1":
            domain = input("Enter the domain to gather more information on: ")
            result = subprocess.run(["python3", "more_mass.py", domain], capture_output=True, text=True)
        elif choice == "2":
            domain = input("Enter domain for DNS Lookup: ")
            result = subprocess.run(["dig", domain], capture_output=True, text=True)
        elif choice == "3":
            target = input("Enter domain for WHOIS Lookup: ")
            result = subprocess.run(["whois", target], capture_output=True, text=True)
        elif choice == "4":
            api_key = input("Enter your Shodan API Key: ")
            target = input("Enter target (IP or domain): ")
            response = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}")
            result = response.json() if response.status_code == 200 else f"Error: {response.json().get('error')}"
        elif choice == "5":
            domain = input("Enter domain for The Harvester: ")
            result = subprocess.run(["theharvester", "-d", domain, "-l", "500", "-b", "all"], capture_output=True, text=True)
        elif choice == "6":
            target = input("Enter target for SpiderFoot: ")
            result = subprocess.run(["spiderfoot", "-s", target], capture_output=True, text=True)
        else:
            return None

        if result:
            if isinstance(result, subprocess.CompletedProcess):
                print(f"\n{Fore.GREEN}Tool Output:\n{result.stdout}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}API Output:\n{result}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")


def scanning():
    print(f"{Fore.CYAN}Scanning & Enumeration{Style.RESET_ALL}")
    # Similar modifications for capturing outputs would go here
    # ...


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
        print("Gaining Access functionality coming soon...")
    elif choice == "4":
        print("Maintaining Access functionality coming soon...")
    elif choice == "5":
        print("Covering Tracks functionality coming soon...")
    elif choice == "6":
        print("Reporting functionality coming soon...")
    elif choice == "7":
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    else:
        main_menu()


if __name__ == "__main__":
    while True:
        try:
            main_menu()
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Interrupted by user. Returning to menu...{Style.RESET_ALL}")
            continue
