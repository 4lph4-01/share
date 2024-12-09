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
    print(f"{Fore.YELLOW}{splash}{Style.RESET_ALL}")


# Columnar Display Helper Function
def display_in_columns(options, column_count=2):
    max_length = max(len(option) for option in options)
    formatted_options = [
        f"[{index+1}] {option:<{max_length}}" 
        for index, option in enumerate(options)
    ]
    for i in range(0, len(formatted_options), column_count):
        print("    ".join(formatted_options[i:i + column_count]))

# OSINT Tools (More_Mass, Shodan, HackerTarget)
def run_osint_tools():
    print(f"{Fore.CYAN}Running OSINT Tools (More_Mass, Shodan, HackerTarget):{Style.RESET_ALL}")

    # OSINT: More_Mass
    try:
        print(f"{Fore.GREEN}Running More_Mass.py for OSINT...{Style.RESET_ALL}")
        subprocess.run(["python3", "more_mass.py"], check=True)
    except Exception as e:
        print(f"{Fore.RED}Error running More_Mass: {e}{Style.RESET_ALL}")

    # OSINT: Shodan
    try:
        print(f"{Fore.GREEN}Running Shodan for OSINT...{Style.RESET_ALL}")
        shodan_api_key = input("Enter your Shodan API Key: ")
        query = input("Enter Shodan query: ")
        response = requests.get(f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={query}")
        print(response.json())
    except Exception as e:
        print(f"{Fore.RED}Error running Shodan: {e}{Style.RESET_ALL}")

    # OSINT: HackerTarget DNS Lookup
    try:
        print(f"{Fore.GREEN}Running HackerTarget DNS Lookup for OSINT...{Style.RESET_ALL}")
        domain = input("Enter the domain for DNS lookup: ")
        response = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        print(response.text)
    except Exception as e:
        print(f"{Fore.RED}Error running HackerTarget DNS Lookup: {e}{Style.RESET_ALL}")

# Gaining Access Tools (Metasploit, SQLMap, Veil Evasion)
def gaining_access_tools():
    print(f"{Fore.CYAN}Running Gaining Access Tools:{Style.RESET_ALL}")
    
    # Metasploit Integration
    try:
        print(f"{Fore.GREEN}Running Metasploit...{Style.RESET_ALL}")
        subprocess.run(["msfconsole", "-q"], check=True)
    except Exception as e:
        print(f"{Fore.RED}Error running Metasploit: {e}{Style.RESET_ALL}")
    
    # SQLMap Integration
    try:
        print(f"{Fore.GREEN}Running SQLMap for SQL Injection Testing...{Style.RESET_ALL}")
        target = input("Enter target URL for SQLMap: ")
        subprocess.run(["sqlmap", "-u", target, "--batch"], check=True)
    except Exception as e:
        print(f"{Fore.RED}Error running SQLMap: {e}{Style.RESET_ALL}")
    
    # Veil Evasion
    try:
        print(f"{Fore.GREEN}Running Veil Evasion for Payload Generation...{Style.RESET_ALL}")
        subprocess.run(["veil-evasion"], check=True)
    except Exception as e:
        print(f"{Fore.RED}Error running Veil Evasion: {e}{Style.RESET_ALL}")

# Main Menu
def main_menu():
    display_splash_screen()

    options = [
        "Methodology",
        "OSINT (Recon)",
        "Scanning & Enumeration",
        "Gaining Access",
        "Reporting",
        "Exit"
    ]
    display_in_columns(options)

    choice = input(f"{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    
    if choice == "1":
        display_methodology()
    elif choice == "2":
        run_osint_tools()
    elif choice == "3":
        print(f"{Fore.RED}Scanning & Enumeration tools coming soon!{Style.RESET_ALL}")
    elif choice == "4":
        gaining_access_tools()
    elif choice == "5":
        generate_report()
    elif choice == "6":
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit()
    else:
        print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        main_menu()

# Display Penetration Test Methodology
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
    main_menu()

# Generate Report
def generate_report():
    print(f"{Fore.GREEN}Generating Report...{Style.RESET_ALL}")
    with open("penetration_test_report.txt", "w") as report_file:
        report_file.write("Penetration Test Report\n")
        report_file.write("======================\n")
        report_file.write(f"Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        report_file.write(f"Test Summary: OSINT tools used, including More_Mass, Shodan, and HackerTarget DNS lookup.\n")

    print(f"{Fore.GREEN}Report generated and saved as 'penetration_test_report.txt'.{Style.RESET_ALL}")
    main_menu()

# Run the program
if __name__ == "__main__":
    main_menu()
