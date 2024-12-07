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
    }===={  }====={  }====={  }======{  }======{  }======={
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

# Main Menu
def display_main_menu():
    print(f"\n{Fore.TEAL}Main Menu:{Style.RESET_ALL}")
    options = [
        "Reconnaissance Tools", 
        "Scanning & Enumeration", 
        "Gaining Access", 
        "Proxies", 
        "Maintaining Access", 
        "Covering Tracks", 
        "Reports & Results", 
        "Methodology", 
        "Exit"
    ]
    display_in_columns(options, column_count=3)

# Sub-menus
def reconnaissance_tools_menu():
    print(f"\n{Fore.TEAL}Reconnaissance Tools:{Style.RESET_ALL}")
    options = [
        "Use 'more_mass' for mass data gathering",
        "Use 'email_address_harvester' for email harvesting",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def scanning_enumeration_menu():
    print(f"\n{Fore.TEAL}Scanning & Enumeration:{Style.RESET_ALL}")
    options = [
        "Network Scan with Nmap",
        "Vulnerability Scan",
        "DNS Enumeration",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def gaining_access_menu():
    print(f"\n{Fore.TEAL}Gaining Access:{Style.RESET_ALL}")
    options = [
        "Launch MSFVenom",
        "Launch Metasploit",
        "Launch Veil",
        "Brute Force with Hydra",
        "Exploit SMB with EternalBlue",
        "Web Shell Upload",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def proxies_menu():
    print(f"\n{Fore.TEAL}Proxies:{Style.RESET_ALL}")
    options = [
        "Configure Proxychains",
        "Test Proxychains Setup",
        "Setup Tor Network",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def maintaining_access_menu():
    print(f"\n{Fore.TEAL}Maintaining Access:{Style.RESET_ALL}")
    options = [
        "Set up Backdoors",
        "Install Persistent Agents",
        "Remote Access Tools",
        "Setup SSH Port Forwarding",
        "Setup MSF Port Forwarding",
        "Apply AMSI Bypass",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def covering_tracks_menu():
    print(f"\n{Fore.TEAL}Covering Tracks:{Style.RESET_ALL}")
    options = [
        "Log File Removal",
        "Clear Bash History",
        "Spoof Network Traffic",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def reports_results_menu():
    print(f"\n{Fore.TEAL}Reports & Results:{Style.RESET_ALL}")
    options = [
        "Generate Summary Report",
        "Export to CSV",
        "View Detailed Logs",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

# Main Function
def main():
    display_splash_screen()

    while True:
        display_main_menu()
        choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
        
        if choice == "1":
            reconnaissance_tools_menu()
        elif choice == "2":
            scanning_enumeration_menu()
        elif choice == "3":
            gaining_access_menu()
        elif choice == "4":
            proxies_menu()
        elif choice == "5":
            maintaining_access_menu()
        elif choice == "6":
            covering_tracks_menu()
        elif choice == "7":
            reports_results_menu()
        elif choice == "8":
            display_methodology()
        elif choice == "9":
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
