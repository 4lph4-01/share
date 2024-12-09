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


# Column Display Helper
def display_in_columns(options):
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")


# Main Methodology Menu
def methodology_menu():
    print(f"\n{Fore.CYAN}Penetration Testing Methodology:{Style.RESET_ALL}")
    options = [
        "Reconnaissance",
        "Scanning and Enumeration",
        "Gaining Access",
        "Setup Proxies",
        "Maintaining Access",
        "Covering Tracks",
        "Exit"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select a phase: {Style.RESET_ALL}"))
        if choice == 1:
            print("Reconnaissance tools (e.g., Nmap, Shodan, OSINT) will be here.")
        elif choice == 2:
            print("Scanning tools (e.g., Nmap, Nikto, enum4linux) will be here.")
        elif choice == 3:
            gaining_access_menu()
        elif choice == 4:
            setup_proxies_menu()
        elif choice == 5:
            maintaining_access_menu()
        elif choice == 6:
            covering_tracks_menu()
        elif choice == 7:
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
            methodology_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        methodology_menu()


# Setup Proxies Menu
def setup_proxies_menu():
    print(f"\n{Fore.CYAN}Setup Proxies:{Style.RESET_ALL}")
    options = [
        "Configure Proxychains",
        "Start Tor Service",
        "Setup SSH Tunnel with Sshuttle",
        "Return to Methodology Menu"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an action: {Style.RESET_ALL}"))
        if choice == 1:
            config_path = "/etc/proxychains.conf"
            print(f"Editing Proxychains configuration at {config_path}...")
            subprocess.run(["sudo", "nano", config_path])
        elif choice == 2:
            print("Starting Tor service...")
            subprocess.run(["sudo", "systemctl", "start", "tor"])
        elif choice == 3:
            target = input("Enter target network (e.g., 192.168.0.0/24): ")
            server = input("Enter SSH server address: ")
            subprocess.run(["sshuttle", "-r", server, target])
        elif choice == 4:
            methodology_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            setup_proxies_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        setup_proxies_menu()


# Gaining Access Menu
def gaining_access_menu():
    print(f"\n{Fore.CYAN}Gaining Access:{Style.RESET_ALL}")
    options = [
        "Launch MSFVenom",
        "Launch Metasploit",
        "Launch Veil",
        "Brute Force with Hydra",
        "Web Shell Upload",
        "NTLM Relay Attack",
        "Return to Methodology Menu"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an action: {Style.RESET_ALL}"))
        if choice == 1:
            print("Launching MSFVenom...")
        elif choice == 2:
            print("Launching Metasploit...")
        elif choice == 3:
            print("Launching Veil...")
        elif choice == 4:
            print("Using Hydra for brute force attacks...")
        elif choice == 5:
            print("Uploading a web shell...")
        elif choice == 6:
            print("Executing NTLM relay attack...")
        elif choice == 7:
            methodology_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            gaining_access_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        gaining_access_menu()


# Maintaining Access Menu
def maintaining_access_menu():
    print(f"\n{Fore.CYAN}Maintaining Access:{Style.RESET_ALL}")
    options = [
        "Use Metasploit Persistence Module",
        "Upload Web Shell with Weevely",
        "Inject SSH Key for Persistent Access",
        "Return to Methodology Menu"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an action: {Style.RESET_ALL}"))
        if choice == 1:
            print("Launching Metasploit persistence module...")
        elif choice == 2:
            print("Uploading web shell with Weevely...")
        elif choice == 3:
            print("Injecting SSH key for persistent access...")
        elif choice == 4:
            methodology_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            maintaining_access_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        maintaining_access_menu()


# Covering Tracks Menu
def covering_tracks_menu():
    print(f"\n{Fore.CYAN}Covering Tracks:{Style.RESET_ALL}")
    options = [
        "Clear Bash History",
        "Modify File Timestamps (Timestomp)",
        "Use Metasploit Anti-Forensics Tools",
        "Return to Methodology Menu"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an action: {Style.RESET_ALL}"))
        if choice == 1:
            print("Clearing Bash history...")
        elif choice == 2:
            print("Modifying file timestamps...")
        elif choice == 3:
            print("Using Metasploit anti-forensics tools...")
        elif choice == 4:
            methodology_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            covering_tracks_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        covering_tracks_menu()


# Main Execution
if __name__ == "__main__":
    display_splash_screen()
    methodology_menu()
