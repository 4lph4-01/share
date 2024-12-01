import os
import subprocess
import time
import sys
import asyncio
import aiohttp
import json
from datetime import datetime

# Define tool checks
def check_tool(tool_name):
    """Check if the tool is installed on the system."""
    try:
        subprocess.run([tool_name, '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

# Banner for the framework
def display_splash_screen():
    splash = """
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
   (______)(_______)(_______)(________)(________)(_________)
   
 
"""

    print(splash)
    print("Penetration Testing Framework 41PH4-01\n")

# Tools and their commands
TOOLS = {
    'sqlmap': 'sqlmap --help',
    'xsstrike': 'xsstrike --help',
    'aircrack-ng': 'airmon-ng --help',
    'metasploit': 'msfvenom --help',
    'evilginx2': 'evilginx2 --help',
    'nmap': 'nmap -v',
    'nessus': 'nessus -h',
    'dnscat2': 'dnscat2 --help',
}

# Global settings
TARGET = None
USER_AGENT = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Tool checking function
def check_tools():
    missing_tools = []
    for tool, command in TOOLS.items():
        if not check_tool(tool):
            missing_tools.append(tool)
    if missing_tools:
        print(f"Warning: Missing tools: {', '.join(missing_tools)}")
    else:
        print("All tools are installed and ready!")

# Phishing Campaign with Evilginx2
def phishing_campaign(report_file):
    print("[*] Starting Phishing Campaign with Evilginx2...")
    result = subprocess.run(["evilginx2", "launch"], capture_output=True, text=True)
    append_to_report(result, report_file)

# SQL Injection with sqlmap
def sql_injection(url, report_file):
    print(f"[*] Running SQL Injection Test on {url}")
    result = subprocess.run([TOOLS['sqlmap'], f"-u {url} --batch"], capture_output=True, text=True)
    append_to_report(result, report_file)

# XSS Testing with XSStrike
def test_xss(url, report_file):
    print(f"[*] Running XSS Testing on {url}")
    result = subprocess.run([TOOLS['xsstrike'], f"-u {url} --batch"], capture_output=True, text=True)
    append_to_report(result, report_file)

# Network Scanning with Nmap
def network_scan(target, report_file):
    print(f"[*] Running Network Scan on {target}")
    result = subprocess.run([TOOLS['nmap'], target], capture_output=True, text=True)
    append_to_report(result, report_file)

# Wi-Fi Deauth Attack with aircrack-ng (captures handshake and attempts to crack key)
def wifi_attack(interface, report_file):
    print(f"[*] Setting {interface} to monitor mode for Wi-Fi attacks...")
    subprocess.run(["airmon-ng", "start", interface])
    print(f"[*] Capturing handshake on {interface}...")
    result = subprocess.run(["airodump-ng", interface, "--write", "capture"], capture_output=True, text=True)
    append_to_report(result, report_file)
    
    # Assuming we have captured the handshake in "capture-01.cap"
    print("[*] Attempting to crack WPA key using aircrack-ng...")
    result = subprocess.run(["aircrack-ng", "capture-01.cap", "-w", "/path/to/wordlist.txt"], capture_output=True, text=True)
    append_to_report(result, report_file)

# Generate a snazzy report
def append_to_report(result, report_file):
    with open(report_file, 'a') as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Output:\n{result.stdout}\n")
        if result.stderr:
            f.write(f"Errors:\n{result.stderr}\n")
        f.write(f"{'='*80}\n")

# Subdomain Enumeration using custom script
async def fetch(session, url):
    """Fetch data from a URL."""
    async with session.get(url) as response:
        return await response.text()

async def get_subdomains(domain):
    """Get subdomains from public sources."""
    subdomains = set()
    urls = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}"
    ]

    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in urls]
        responses = await asyncio.gather(*tasks)

        for response in responses:
            if response.startswith('['):  # JSON response from crt.sh
                json_response = json.loads(response)
                for item in json_response:
                    subdomains.add(item['name_value'])
            else:  # Plain text response from hackertarget
                lines = response.split('\n')
                for line in lines:
                    if line:
                        subdomains.add(line.split(',')[0])

    return list(subdomains)

def run_subdomain_enum(domain, report_file):
    print(f"[*] Running Subdomain Enumeration for {domain}")
    subdomains = asyncio.run(get_subdomains(domain))
    result = "\n".join(subdomains)
    append_to_report(result, report_file)

# Main Menu System
def main_menu():
    while True:
        print("\n[+] Penetration Testing Framework")
        print("1. Website Vulnerability Testing")
        print("2. Wi-Fi Cracking")
        print("3. Subdomain Enumeration")
        print("4. Network Scanning")
        print("5. Exit")
        
        choice = input("Select an option: ")
        
        if choice == '1':
            website_testing_menu()
        elif choice == '2':
            wifi_cracking_menu()
        elif choice == '3':
            subdomain_enum_menu()
        elif choice == '4':
            network_scan_menu()
        elif choice == '5':
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid choice. Please select a valid option.")

# Website Testing Menu
def website_testing_menu():
    print("\n[+] Website Vulnerability Testing")
    print("1. SQL Injection")
    print("2. XSS Testing")
    print("3. Go Back")
    
    choice = input("Select an option: ")
    if choice == '1':
        url = input("[*] Enter the URL for SQL Injection testing: ")
        report_file = "penetration_testing_report.txt"
        sql_injection(url, report_file)
    elif choice == '2':
        url = input("[*] Enter the URL for XSS testing: ")
        report_file = "penetration_testing_report.txt"
        test_xss(url, report_file)
    elif choice == '3':
        return
    else:
        print("Invalid choice. Please select a valid option.")

# Wi-Fi Cracking Menu
def wifi_cracking_menu():
    print("\n[+] Wi-Fi Cracking")
    print("1. Start Deauth Attack and Cracking")
    print("2. Go Back")
    
    choice = input("Select an option: ")
    if choice == '1':
        interface = input("[*] Enter your Wi-Fi interface (e.g., wlan0): ")
        report_file = "penetration_testing_report.txt"
        wifi_attack(interface, report_file)
    elif choice == '2':
        return
    else:
        print("Invalid choice. Please select a valid option.")

# Subdomain Enumeration Menu
def subdomain_enum_menu():
    print("\n[+] Subdomain Enumeration")
    domain = input("[*] Enter the domain to enumerate: ")
    report_file = "penetration_testing_report.txt"
    run_subdomain_enum(domain, report_file)

# Network Scanning Menu
def network_scan_menu():
    print("\n[+] Network Scanning")
    target = input("[*] Enter target IP or network to scan: ")
    report_file = "penetration_testing_report.txt"
    network_scan(target, report_file)

# Start the script
if __name__ == "__main__":
    display_splash_screen()
    check_tools()
    main_menu()
