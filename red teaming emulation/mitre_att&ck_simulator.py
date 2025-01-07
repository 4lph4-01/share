######################################################################################################################################################################################################################
# Python adversary emulation simulator, in line with the MITRE ATT&CK Framerwork. sudo python3 mitre_att&ck.py. Requires a linux virtual environment. Performs non-destructive simulations based on selections. 
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

# Main simulation function
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

if __name__ == "__main__":
    run_simulation()

