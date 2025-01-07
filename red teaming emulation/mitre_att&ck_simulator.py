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
import requests
import subprocess
import time
import os

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

# Tool check and installation function
def check_tool_installed(tool_name, install_command):
    """Check if a tool is installed, prompt to install if not."""
    try:
        subprocess.check_call([tool_name, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[INFO] {tool_name} is already installed.")
    except subprocess.CalledProcessError:
        print(f"[ERROR] {tool_name} is not installed.")
        install = input(f"Do you want to install {tool_name}? (y/n): ").lower()
        if install == 'y':
            print(f"[INFO] Installing {tool_name}...")
            subprocess.check_call(install_command, shell=True)
        else:
            print(f"[ERROR] {tool_name} is required for Penetration Testing Mode. Exiting.")
            exit(1)

# Download MITRE ATT&CK data if not already downloaded
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

# Display available APT groups
def display_apt_groups(data):
    apt_groups = [group['name'] for group in data['objects'] if group['type'] == 'intrusion-set']
    print("Select an APT Group:")
    for i, group in enumerate(apt_groups, 1):
        print(f"{i}. {group}")
    return apt_groups

# Display available techniques for the selected APT group
def display_techniques(data, selected_group):
    techniques = []
    for obj in data['objects']:
        if obj['type'] == 'attack-pattern' and selected_group in [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]:
            techniques.append(obj['name'])
    print("\nSelect Techniques to simulate:")
    for i, technique in enumerate(techniques, 1):
        print(f"{i}. {technique}")
    return techniques

# Simulate the selected techniques
def simulate_technique(apt_group, technique):
    print(f"\n[INFO] Simulating {technique} for APT Group: {apt_group}...")
    time.sleep(2)  # Simulate execution time
    print(f"[INFO] Simulation for {technique} complete.\n")

# Generate text report
def generate_text_report(apt_group, techniques):
    with open(f"{apt_group}_report.txt", 'w') as report_file:
        report_file.write(f"APT Group: {apt_group}\n\n")
        for technique in techniques:
            report_file.write(f"- {technique}\n")
    print(f"[INFO] Report generated: {apt_group}_report.txt")

# Generate HTML report
def generate_html_report(apt_group, techniques):
    with open(f"{apt_group}_report.html", 'w') as report_file:
        report_file.write(f"<html><body><h1>APT Group: {apt_group}</h1><ul>\n")
        for technique in techniques:
            report_file.write(f"<li>{technique}</li>\n")
        report_file.write("</ul></body></html>")
    print(f"[INFO] Report generated: {apt_group}_report.html")

# Select IP address for target
def select_target_ip():
    """Prompt the user for a target IP address."""
    target_ip = input("Enter the target IP address: ")
    print(f"[INFO] Target IP selected: {target_ip}")
    return target_ip

# Execute CrackMapExec for SMB attacks
def run_crackmapexec(target_ip):
    print(f"[INFO] Running CrackMapExec against {target_ip}...")
    subprocess.run(['crackmapexec', 'smb', target_ip, '--shares'])

# Execute Empire for post-exploitation
def run_empire(target_ip):
    print(f"[INFO] Running Empire agent against {target_ip}...")
    subprocess.run(['empire', '--agent', target_ip, '--target', target_ip])

# Penetration testing mode function
def run_penetration_testing():
    """Penetration testing using real tools (CrackMapExec, Empire)."""
    # Ensure tools are installed
    check_tool_installed('crackmapexec', 'pip install crackmapexec')
    check_tool_installed('empire', 'pip install empire')

    # Select target IP for attack
    target_ip = select_target_ip()

    # Select APT group and techniques for attack
    apt_groups = display_apt_groups(data)
    apt_group_selection = int(input(f"\nEnter selection (1-{len(apt_groups)}): "))
    selected_group = apt_groups[apt_group_selection - 1]
    print(f"[INFO] You selected: {selected_group}")
    
    techniques = display_techniques(data, selected_group)
    selected_techniques = []
    while True:
        technique_selection = int(input(f"\nSelect a technique (1-{len(techniques)}), or 0 to finish: "))
        if technique_selection == 0:
            break
        selected_technique = techniques[technique_selection - 1]
        selected_techniques.append(selected_technique)
        
        # Execute attack tools (CrackMapExec, Empire)
        if 'SMB' in selected_technique:
            run_crackmapexec(target_ip)
        elif 'Empire' in selected_technique:
            run_empire(target_ip)
        else:
            print(f"[ERROR] No matching tool for technique: {selected_technique}")

    # Report Generation (same as simulation)
    report_format = input("Generate report in text or HTML format? (text/html): ").lower()
    if report_format == 'text':
        generate_text_report(selected_group, selected_techniques)
    elif report_format == 'html':
        generate_html_report(selected_group, selected_techniques)
    else:
        print("[ERROR] Invalid report format.")

# Mode selection function
def select_mode():
    """Allow the user to select between simulation and penetration testing mode."""
    print("\nSelect Mode:")
    print("1. Simulation Mode (ATT&CK-based)")
    print("2. Penetration Testing Mode (Real Attacks using tools)")

    mode = int(input("Enter selection (1 or 2): "))
    
    if mode == 1:
        run_simulation()  # Existing simulation function
    elif mode == 2:
        run_penetration_testing()  # New penetration testing function
    else:
        print("[ERROR] Invalid mode selected.")
        exit(1)

# Simulation Mode function
def run_simulation():
    """Run the MITRE ATT&CK simulation."""
    #
