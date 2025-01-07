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


# Load APT group data from JSON file
def load_apt_groups(filename="apt_groups.json"):
    with open(filename, "r") as file:
        return json.load(file)

# Function to display APT group details
def display_apt_details(apt_name, apt_details):
    print(f"\n[INFO] {apt_name}: {apt_details['description']}\n")

# Function to display technique details
def display_technique_details(technique):
    print(f"\n[INFO] Technique: {technique['name']} ({technique['id']})")
    print(f"Tactic: {technique['tactic']}")
    print(f"Description: {technique['description']}\n")

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
    print(f"[ALERT] Generated alert for {technique['name']} ({technique['id']})")

# Function to simulate a wide range of attack techniques
def simulate_technique(apt_name, technique):
    print(f"[INFO] Simulating technique {technique['name']} ({technique['id']}) for {apt_name}...")

    # Map technique IDs to simulation functions
    technique_simulation_map = {
        "T1071": simulate_http_requests,
        "T1059": simulate_command_execution,
        "T1089": simulate_disable_security_tools,
        # Add more mappings here as needed
    }

    # Call the corresponding simulation function if it exists
    simulate_func = technique_simulation_map.get(technique["id"], simulate_generic_activity)
    simulate_func()

    print(f"[INFO] {technique['name']} simulation complete.\n")
    # Generate an alert for the simulated technique
    log_alert(apt_name, technique)

def simulate_http_requests():
    # Simulate HTTP requests using PowerShell
    endpoints = ["http://example.com", "http://example.org", "http://example.net"]
    for endpoint in endpoints:
        subprocess.run(["powershell", "-Command", f"Invoke-WebRequest -Uri {endpoint} -UseBasicParsing"])
        time.sleep(1)

def simulate_command_execution():
    # Simulate command execution using PowerShell
    commands = [
        "Get-Process",
        "Get-Service",
        "Write-Output 'Simulating APT activity' > C:\\Temp\\apt_simulation.log"
    ]
    for command in commands:
        subprocess.run(["powershell", "-Command", command])
        time.sleep(1)

def simulate_disable_security_tools():
    # Simulate disabling security tools using PowerShell
    security_commands = [
        "Stop-Service -Name 'WinDefend' -Force",  # Stop Windows Defender
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"  # Disable Windows Firewall
    ]
    for command in security_commands:
        subprocess.run(["powershell", "-Command", command])
        time.sleep(1)

def simulate_generic_activity():
    # Simulate generic activity for techniques not specifically mapped
    subprocess.run(["powershell", "-Command", "Write-Output 'Simulating generic APT activity' > C:\\Temp\\generic_apt_simulation.log"])
    time.sleep(1)

# Main function to run the simulation
def run_simulation():
    apt_groups = load_apt_groups()  # Load APT group data
    print("[INFO] APT Groups loaded.")

    # Loop through each APT group
    for apt_name, apt_details in apt_groups.items():
        display_apt_details(apt_name, apt_details)

        # Loop through each technique in the APT group
        for technique in apt_details["techniques"]:
            display_technique_details(technique)
            simulate_technique(apt_name, technique)

    print("[INFO] Simulation complete. Check alerts_log.json for generated alerts.")

if __name__ == "__main__":
    run_simulation()
