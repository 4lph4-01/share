######################################################################################################################################################################################################################
# ###Under Construction### Python adversary emulation simulator, in line with the MITRE ATT&CK Framerwork. sudo python3 mitre_att&ck.py. Requires a linux virtual environment. Performs simulations or real world attacks based on selections. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import json
import subprocess
import os
import requests
import time

# Disclaimer to ensure ethical use
def display_disclaimer():
    print("""
    WARNING: This script contains functionality for both penetration testing and simulation of APT groups.
    
    By using this tool, you acknowledge and agree that:
    - You have explicit permission to conduct penetration tests on the target systems.
    - You will not use this tool for unauthorized access or malicious activities.
    - You understand the potential risks involved in executing real penetration tests, including system disruption or data loss.
    - The authors of this tool are not responsible for any damage or legal consequences resulting from its use.
    
    Proceeding without proper authorization is illegal and unethical. Do you acknowledge and accept these terms? (y/n)
    """)

    response = input("Enter 'y' to accept or 'n' to decline: ").lower()
    if response != 'y':
        print("[ERROR] You must accept the disclaimer to continue.")
        exit(1)
    else:
        print("[INFO] You have accepted the disclaimer. Proceeding...")


# MITRE ATT&CK data URL (latest JSON dataset)
ATTACK_DATA_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Load the MITRE ATT&CK data (download it if necessary)
def download_attack_data():
    response = requests.get(ATTACK_DATA_URL)
    if response.status_code == 200:
        with open('attack_data.json', 'w') as f:
            f.write(response.text)
        print("[INFO] MITRE ATT&CK data downloaded successfully.")
    else:
        print("[ERROR] Failed to download MITRE ATT&CK data.")
        return None
    return 'attack_data.json'

# Check if tools are installed (CrackMapExec, Empire, SearchSploit)
def check_tools():
    tools = {
        'nmap': 'nmap --version',
        'searchsploit': 'searchsploit --version',
        'crackmapexec': 'crackmapexec --version',
        'empire': 'empire --version'
    }

    for tool, command in tools.items():
        print(f"[INFO] Checking if {tool} is installed...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] {tool} is not installed. Please install {tool}.")
            return False
    return True

# Run Nmap scan to detect open ports and services
def nmap_scan(target_ip):
    print(f"[INFO] Running Nmap scan on {target_ip}...")
    nmap_command = f"nmap -sV -O {target_ip}"  # -sV for version detection, -O for OS detection
    result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
    print(result.stdout)
    return result.stdout  # Return Nmap scan results for further processing

# Search for known vulnerabilities with SearchSploit
def searchsploit_vulnerabilities(service_name, version):
    print(f"[INFO] Searching for vulnerabilities for {service_name} {version}...")
    search_command = f"searchsploit {service_name} {version}"
    result = subprocess.run(search_command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[INFO] Vulnerabilities found:\n{result.stdout}")
        return result.stdout
    else:
        print(f"[INFO] No vulnerabilities found for {service_name} {version}.")
        return None

# Run CrackMapExec for SMB or other services
def run_crackmapexec(target_ip):
    print(f"[INFO] Running CrackMapExec against {target_ip}...")
    subprocess.run(['crackmapexec', 'smb', target_ip, '--shares'])

# Example of post-exploitation with Empire (adjust for actual Empire usage)
def run_empire_post_exploitation(target_ip):
    print(f"[INFO] Running Empire post-exploitation module against {target_ip}...")
    subprocess.run(['empire', 'agent', 'new', 'listener', 'http', '--ip', target_ip])

# Function to run a penetration test (with vulnerability detection)
def run_penetration_testing():
    # User input for target IP
    target_ip = input("Enter the target IP address: ")

    # Perform Nmap scan to detect services and version
    nmap_results = nmap_scan(target_ip)

    # Sample extraction from Nmap output (this can be more sophisticated)
    # Let's assume the Nmap output indicates an Apache service version
    service_name = "Apache"
    service_version = "2.4.7"

    # Cross-reference with SearchSploit for known vulnerabilities
    vulnerabilities = searchsploit_vulnerabilities(service_name, service_version)

    # If vulnerabilities found, try to exploit them (simplified)
    if vulnerabilities:
        print(f"[INFO] Found vulnerabilities in {service_name} {service_version}. Attempting to exploit...")
        # Add exploit attempt logic here (e.g., using Metasploit, etc.)

    # Run CrackMapExec for SMB if SMB service is detected
    if 'smb' in nmap_results.lower():
        run_crackmapexec(target_ip)

    # Run Empire for post-exploitation if needed
    if 'ssh' in nmap_results.lower():
        run_empire_post_exploitation(target_ip)

# Main function to choose penetration testing or simulation mode
def select_mode():
    print("\nSelect Mode:")
    print("1. Simulation Mode (ATT&CK-based)")
    print("2. Penetration Testing Mode (Real Attacks using tools)")

    mode = int(input("Enter selection (1 or 2): "))

    if mode == 1:
        # Existing simulation function
        run_simulation()
    elif mode == 2:
        if check_tools():  # Check if necessary tools are installed
            run_penetration_testing()  # New penetration testing function
        else:
            print("[ERROR] Missing required tools. Please install all necessary tools.")
    else:
        print("[ERROR] Invalid mode selected.")
        exit(1)

# Existing simulation function (from previous parts)
def run_simulation():
    # Step 1: Check if ATT&CK data exists or download it
    if not os.path.exists('attack_data.json'):
        print("[INFO] ATT&CK data not found. Downloading...")
        download_attack_data()
    data = load_attack_data()  # Load the ATT&CK dataset

    # Step 2: Display available APT groups and let user select
    apt_groups = display_apt_groups(data)
    apt_group_selection = int(input(f"\nEnter selection (1-{len(apt_groups)}): "))
    selected_group = apt_groups[apt_group_selection - 1]
    print(f"[INFO] You selected: {selected_group}")

    # Step 3: Display techniques for the selected APT group
    techniques = display_techniques(data, selected_group)
    selected_techniques = []
    while True:
        technique_selection = int(input(f"\nSelect a technique (1-{len(techniques)}), or 0 to finish: "))
        if technique_selection == 0:
            break
        selected_technique = techniques[technique_selection - 1]
        selected_techniques.append(selected_technique)
        simulate_technique(selected_group, selected_technique)

    # Step 4: Report Generation
    report_format = input("Generate report in text or HTML format? (text/html): ").lower()
    if report_format == 'text':
        generate_text_report(selected_group, selected_techniques)
    elif report_format == 'html':
        generate_html_report(selected_group, selected_techniques)
    else:
        print("[ERROR] Invalid report format.")

# Main execution
if __name__ == "__main__":
    select_mode()
