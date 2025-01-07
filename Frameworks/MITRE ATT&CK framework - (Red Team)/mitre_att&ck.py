######################################################################################################################################################################################################################
# ###Under Construction### Python adversary emulation simulator, in line with the MITRE ATT&CK Framerwork. sudo python3 mitre_att&ck.py. Requires a linux virtual environment. 
# Performs simulations or real world attacks based on selections. Note: Will be adding options for real world penatration test attack selection will attempt to exploit discovered vulnerabilities based on logic. 
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

# Function to simulate an attack technique
def simulate_technique(apt_name, technique):
    print(f"[INFO] Simulating technique {technique['name']} ({technique['id']}) for {apt_name}...")
    time.sleep(2)  # Simulating the attack technique (placeholder)
    print(f"[INFO] {technique['name']} simulation complete.\n")

# Main function to run the simulation
def run_simulation():
    apt_groups = load_apt_groups()  # Load APT group data
    print("[INFO] APT Groups loaded.")

    # Show menu for selecting APT group
    print("\nSelect an APT group to simulate:")
    for i, apt_name in enumerate(apt_groups.keys(), 1):
        print(f"{i}. {apt_name}")

    selection = int(input(f"Enter your selection (1-{len(apt_groups)}): "))
    selected_group = list(apt_groups.keys())[selection - 1]
    print(f"[INFO] You selected: {selected_group}")

    # Display APT group details
    display_apt_details(selected_group, apt_groups[selected_group])

    # Show menu for selecting techniques
    selected_techniques = []
    for technique in apt_groups[selected_group]["techniques"]:
        display_technique_details(technique)
        simulate = input(f"Simulate technique {technique['name']}? (y/n): ").lower()
        if simulate == 'y':
            selected_techniques.append(technique)

    # Run simulations for selected techniques
    for technique in selected_techniques:
        simulate_technique(selected_group, technique)

    # Generate reports
    report_format = input("Generate report in text or HTML format? (text/html): ").lower()
    if report_format == "text":
        generate_report_text(selected_group, selected_techniques)
    elif report_format == "html":
        generate_report_html(selected_group, selected_techniques)
    else:
        print("[ERROR] Invalid report format selected.")

def generate_report_text(apt_group, techniques):
    with open(f"{apt_group}_simulation_report.txt", "w") as file:
        file.write(f"Simulation Report for {apt_group}\n")
        file.write("=" * 50 + "\n")
        for technique in techniques:
            file.write(f"- {technique['name']} ({technique['id']})\n")
            file.write(f"  Tactic: {technique['tactic']}\n")
            file.write(f"  Description: {technique['description']}\n")
        print(f"[INFO] Report saved as {apt_group}_simulation_report.txt")

def generate_report_html(apt_group, techniques):
    with open(f"{apt_group}_simulation_report.html", "w") as file:
        file.write(f"<h1>Simulation Report for {apt_group}</h1>\n")
        file.write("<hr>\n")
        for technique in techniques:
            file.write(f"<h2>{technique['name']} ({technique['id']})</h2>\n")
            file.write(f"<p><strong>Tactic:</strong> {technique['tactic']}</p>\n")
            file.write(f"<p><strong>Description:</strong> {technique['description']}</p>\n")
        print(f"[INFO] Report saved as {apt_group}_simulation_report.html")

if __name__ == "__main__":
    run_simulation()
