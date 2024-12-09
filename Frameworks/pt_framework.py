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


import os
import subprocess
import sys
import shutil
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
    print(f"{Fore.CYAN}{splash}{Style.RESET_ALL}")

# Check and Install Tools
def check_tool(tool_name, install_command):
    if shutil.which(tool_name):
        print(f"{Fore.GREEN}{tool_name} is already installed.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}{tool_name} is not installed.{Style.RESET_ALL}")
        choice = input(f"Do you want to install {tool_name}? (y/n): ").lower()
        if choice == "y":
            subprocess.run(install_command, shell=True)
        else:
            print(f"{Fore.YELLOW}Skipping installation of {tool_name}.{Style.RESET_ALL}")

def install_required_tools():
    tools = {
        "nmap": "sudo apt-get install -y nmap",
        "hydra": "sudo apt-get install -y hydra",
        "msfvenom": "sudo apt-get install -y metasploit-framework",
        "veil": "sudo apt-get install -y veil",
        "impacket": "pip install impacket"
    }
    for tool, command in tools.items():
        check_tool(tool, command)

# Methodology Menu
def penetration_test_methodology():
    print("\nPenetration Testing Methodology:")
    options = [
        "Network Discovery",
        "Port Scanning with Nmap",
        "Vulnerability Scanning",
        "Return to Main Menu"
    ]
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")
    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}"))
        if choice == 1:
            network_discovery()
        elif choice == 2:
            port_scanning()
        elif choice == 3:
            vulnerability_scanning()
        elif choice == 4:
            main_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            penetration_test_methodology()
    except ValueError:
        print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
        penetration_test_methodology()

# Example Methodology Actions
def network_discovery():
    print(f"{Fore.CYAN}Performing Network Discovery...{Style.RESET_ALL}")
    subprocess.run(["nmap", "-sn", "192.168.0.0/24"])

def port_scanning():
    print(f"{Fore.CYAN}Performing Port Scanning...{Style.RESET_ALL}")
    target = input("Enter target IP or domain: ")
    subprocess.run(["nmap", "-sS", target])

def vulnerability_scanning():
    print(f"{Fore.CYAN}Performing Vulnerability Scanning...{Style.RESET_ALL}")
    subprocess.run(["nmap", "--script", "vuln", "192.168.0.1"])

# Gaining Access Menu
def gaining_access_menu():
    print("\nGaining Access:")
    options = [
        "Launch MSFVenom",
        "Launch Metasploit",
        "Brute Force with Hydra",
        "Return to Main Menu"
    ]
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")
    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}"))
        if choice == 1:
            subprocess.run(["msfvenom"])
        elif choice == 2:
            subprocess.run(["msfconsole"])
        elif choice == 3:
            target = input("Enter target IP: ")
            username = input("Enter username: ")
            password_list = input("Enter path to password list: ")
            subprocess.run(["hydra", "-l", username, "-P", password_list, target])
        elif choice == 4:
            main_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            gaining_access_menu()
    except ValueError:
        print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
        gaining_access_menu()

# Main Menu
def main_menu():
    display_splash_screen()
    install_required_tools()
    options = [
        "Penetration Testing Methodology",
        "Gaining Access Menu",
        "Exit"
    ]
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")
    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}"))
        if choice == 1:
            penetration_test_methodology()
        elif choice == 2:
            gaining_access_menu()
        elif choice == 3:
            print(f"{Fore.GREEN}Exiting the program. Goodbye!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            main_menu()
    except ValueError:
        print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
        main_menu()

# Entry Point
if __name__ == "__main__":
    main_menu()
