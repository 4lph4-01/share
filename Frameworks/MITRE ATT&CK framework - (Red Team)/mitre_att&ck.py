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

import os
import json
import subprocess
import requests
import time
from termcolor import colored

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

   _____  .___________________________________    _______________________________  _________   ____  __. ___________                                                  __                  _____  ____.____   __________  ___ ___    _____           _______  ____ 
  /     \ |   \__    ___/\______   \_   _____/   /  _  \__    ___/\__    ___/  _ \ \_   ___ \ |    |/ _| \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
 /  \ /  \|   | |    |    |       _/|    __)_   /  /_\  \|    |     |    |  >  _ </|    \  \/ |      <    |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
/    Y    \   | |    |    |    |   \|        \ /    |    \    |     |    | /  <_\ \|     \____|    |  \   |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
\____|__  /___| |____|    |____|_  /_______  / \____|__  /____|     |____| \_____\ \\______  /|____|__ \  \___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
        \/                       \/        \/          \/                         \/       \/         \/      \/                \/       \/     \/                        \/                |__|             \/               \/      |__|                 \/     


                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/
                                 /\      {====}     )___(
                      (\=,      //\\      )__(     /_____\
      __    |'-'-'|  //  .\    (    )    /____\     |   |
     /  \   |_____| (( \_  \    )__(      |  |      |   |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)


    """

    print(splash)
    print("MITRE ATT&CK Framerwork 41PH4-01\n")

# MITRE ATT&CK data URL
ATTACK_DATA_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# File paths for reports
TEXT_REPORT_PATH = "attack_simulation_report.txt"
HTML_REPORT_PATH = "attack_simulation_report.html"

# Download MITRE ATT&CK data if not present
def download_attack_data():
    print("[INFO] Downloading MITRE ATT&CK data...")
    response = requests.get(ATTACK_DATA_URL)
    if response.status_code == 200:
        with open('attack_data.json', 'w') as f:
            f.write(response.text)
        print("[INFO] MITRE ATT&CK data downloaded successfully.")
    else:
        print("[ERROR] Failed to download MITRE ATT&CK data.")
        return None
    return 'attack_data.json'

# Load MITRE ATT&CK data
def load_attack_data(filename='attack_data.json'):
    with open(filename, 'r') as f:
        data = json.load(f)
    return data

# Display available APT groups
def display_apt_groups(data):
    apt_groups = [group['name'] for group in data['objects'] if group['type'] == 'intrusion-set']
    print("\nSelect an APT Group to simulate:")
    for i, group in enumerate(apt_groups, 1):
        print(f"{i}. {group}")
    return apt_groups

# Display techniques for selected APT group
def display_techniques(data, selected_group):
    techniques = []
    for obj in data['objects']:
        if obj['type'] == 'attack-pattern' and selected_group in [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]:
            techniques.append(obj['name'])
    print("\nSelect Techniques to simulate:")
    for i, technique in enumerate(techniques, 1):
        print(f"{i}. {technique}")
    return techniques

# Simulate the selected technique
def simulate_technique(apt_group, technique):
    print(f"\n[INFO] Simulating {technique} for APT Group: {apt_group}...")
    time.sleep(2)  # Simulate execution time
    print(f"[INFO] Simulation for {technique} complete.\n")

# Generate text report
def generate_text_report(apt_group, techniques):
    with open(TEXT_REPORT_PATH, 'w') as report_file:
        report_file.write(f"APT Group: {apt_group}\n\n")
        for technique in techniques:
            report_file.write(f"- {technique}\n")
    print(f"[INFO] Report generated: {TEXT_REPORT_PATH}")

# Generate HTML report
def generate_html_report(apt_group, techniques):
    with open(HTML_REPORT_PATH, 'w') as report_file:
        report_file.write(f"<html><body><h1>APT Group: {apt_group}</h1><ul>\n")
        for technique in techniques:
            report_file.write(f"<li>{technique}</li>\n")
        report_file.write("</ul></body></html>")
    print(f"[INFO] Report generated: {HTML_REPORT_PATH}")

# Interactive menu to run penetration testing
def run_penetration_testing():
    print("\nPenetration Testing Mode Selected.")
    tools = ['CrackMapExec', 'Empire', 'Metasploit', 'Nessus', 'OpenVAS', 'Searchsploit', 'Exploit Suggester']
    print("Select a tool to use for penetration testing:")
    for i, tool in enumerate(tools, 1):
        print(f"{i}. {tool}")
    tool_choice = int(input("Enter your choice (1-7): "))

    if tool_choice == 1:
        tool_name = 'CrackMapExec'
        print(f"Selected {tool_name} for scanning.")
        # Implement CrackMapExec scan here...
    elif tool_choice == 2:
        tool_name = 'Empire'
        print(f"Selected {tool_name} for post-exploitation.")
        # Implement Empire post-exploitation here...
    elif tool_choice == 3:
        tool_name = 'Metasploit'
        print(f"Selected {tool_name} for exploitation.")
        # Implement Metasploit exploitation here...
    elif tool_choice == 4:
        tool_name = 'Nessus'
        print(f"Selected {tool_name} for vulnerability scanning.")
        # Implement Nessus scan here...
    elif tool_choice == 5:
        tool_name = 'OpenVAS'
        print(f"Selected {tool_name} for vulnerability scanning.")
        # Implement OpenVAS scan here...
    elif tool_choice == 6:
        tool_name = 'Searchsploit'
        print(f"Selected {tool_name} for vulnerability search.")
        # Implement Searchsploit here...
    elif tool_choice == 7:
        tool_name = 'Exploit Suggester'
        print(f"Selected {tool_name} for exploit suggestions.")
        # Implement Exploit Suggester here...
    else:
        print("[ERROR] Invalid tool selection.")
        return None

    return tool_name

# Vulnerability scanning and exploitation logic
def scan_and_exploit(target_ip, tool):
    print(f"Scanning target {target_ip} using {tool}...")
    if tool == 'Searchsploit':
        # Example: Running searchsploit for a specific vulnerability
        searchsploit_command = f"searchsploit {target_ip}"
        subprocess.run(searchsploit_command, shell=True)

    elif tool == 'Exploit Suggester':
        # Example: Running exploit suggester from Metasploit
        exploit_suggester_command = f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={target_ip} LPORT=4444 -f exe"
        subprocess.run(exploit_suggester_command, shell=True)

    elif tool == 'Nessus':
        # Implement Nessus scan command
        pass
    elif tool == 'OpenVAS':
        # Implement OpenVAS scan command
        pass

# Main simulation function
def run_simulation():
    # Disclaimer
    print(colored("WARNING: This tool is for ethical hacking purposes only!", 'red'))
    time.sleep(1)

    if not os.path.exists('attack_data.json'):
        print("[INFO] MITRE ATT&CK data not found. Downloading...")
        download_attack_data()

    data = load_attack_data()

    # Choose between Simulation and Penetration Testing
    mode = input("Select mode: (1) Simulation, (2) Penetration Testing: ")

    if mode == '1':  # Simulation mode
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
            simulate_technique(selected_group, selected_technique)

        report_format = input("Generate report in text or HTML format? (text/html): ").lower()
        if report_format == 'text':
            generate_text_report(selected_group, selected_techniques)
        elif report_format == 'html':
            generate_html_report(selected_group, selected_techniques)
        else:
            print("[ERROR] Invalid report format.")
    elif mode == '2':  # Penetration Testing Mode
        target_ip = input("Enter the target IP: ")
        tool_name = run_penetration_testing()
        scan_and_exploit(target_ip, tool_name)
    else:
        print("[ERROR] Invalid mode selection.")

if __name__ == "__main__":
    run_simulation()
