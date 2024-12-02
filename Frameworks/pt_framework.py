import subprocess
import sys
import os
import time
from colorama import Fore, Style

# Splash Screen
def display_splash_screen():
    splash = """
_____________________  ___________                                                  __                  _____  ____.____   __________  ___ ___    _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
                 /_____/    \/                \/       \/     \/                        \/                |__|             \/               \/      |__|                 \/     
    
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

# Main Menu
def display_main_menu():
    print(f"\n{Fore.TEAL}Main Menu:{Style.RESET_ALL}")
    options = [
        "Exploitation Tools", 
        "Reconnaissance Tools", 
        "Scanning & Enumeration", 
        "Proxies", 
        "Gaining Access", 
        "Maintaining Access", 
        "Covering Tracks", 
        "Reports & Results", 
        "Exit"
    ]
    display_in_columns(options, column_count=3)

# Sub-menus
def exploitation_tools_menu():
    print(f"\n{Fore.TEAL}Exploitation Tools:{Style.RESET_ALL}")
    options = [
        "Launch MSFVenom", 
        "Launch Metasploit", 
        "Launch Veil", 
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

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

def proxies_menu():
    print(f"\n{Fore.TEAL}Proxies:{Style.RESET_ALL}")
    options = [
        "Configure Proxychains",
        "Test Proxychains Setup",
        "Setup Tor Network",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def gaining_access_menu():
    print(f"\n{Fore.TEAL}Gaining Access:{Style.RESET_ALL}")
    options = [
        "Brute Force with Hydra",
        "Exploit SMB with EternalBlue",
        "Web Shell Upload",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

def maintaining_access_menu():
    print(f"\n{Fore.TEAL}Maintaining Access:{Style.RESET_ALL}")
    options = [
        "Set up Backdoors",
        "Install Persistent Agents",
        "Remote Access Tools",
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
            exploitation_tools_menu()
        elif choice == "2":
            reconnaissance_tools_menu()
        elif choice == "3":
            scanning_enumeration_menu()
        elif choice == "4":
            proxies_menu()
        elif choice == "5":
            gaining_access_menu()
        elif choice == "6":
            maintaining_access_menu()
        elif choice == "7":
            covering_tracks_menu()
        elif choice == "8":
            reports_results_menu()
        elif choice == "9":
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
