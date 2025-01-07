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


# Load APT group data from the JSON file
def load_apt_groups(filename="apt_groups.json"):
    with open(filename, "r") as file:
        return json.load(file)

# Function to simulate an attack technique
def simulate_technique(apt_name, technique):
    print(f"[INFO] Simulating technique {technique['name']} (ID: {technique['id']}, Tactic: {technique['tactic']}) for {apt_name}...")
    time.sleep(2)  # Placeholder for simulation logic
    print(f"[INFO] {technique['name']} simulation complete.\n")

# Generate text report
def generate_report_text(apt_name, techniques):
    filename = f"{apt_name}_simulation_report.txt"
    with open(filename, "w") as file:
        file.write(f"Simulation Report for {apt_name}\n")
        file.write("=" * 40 + "\n")
        for technique in techniques:
            file.write(f"- Technique: {technique['name']} (ID: {technique['id']}, Tactic: {technique['tactic']})\n")
    print(f"[INFO] Text report generated: {filename}")

# Generate HTML report
def generate_report_html(apt_name, techniques):
    filename = f"{apt_name}_simulation_report.html"
    with open(filename, "w") as file:
        file.write(f"<html><body><h1>Simulation Report for {apt_name}</h1><ul>")
        for technique in techniques:
            file.write(f"<li>Technique: {technique['name']} (ID: {technique['id']}, Tactic: {technique['tactic']})</li>")
        file.write("</ul></body></html>")
    print(f"[INFO] HTML report generated: {filename}")

# Main function to run the simulation
def run_simulation():
    apt_groups = load_apt_groups()  # Load APT group data
    print("[INFO] APT Groups loaded.")

    # Show menu for selecting an APT group
    print("\nSelect an APT group to simulate:")
    for i, apt_name in enumerate(apt_groups.keys(), 1):
        print(f"{i}. {apt_name}")

    while True:
        try:
            selection = int(input(f"Enter your selection (1-{len(apt_groups)}): "))
            if 1 <= selection <= len(apt_groups):
                break
            else:
                print("[ERROR] Invalid selection. Please try again.")
        except ValueError:
            print("[ERROR] Invalid input. Please enter a number.")

    selected_group = list(apt_groups.keys())[selection - 1]
    print(f"[INFO] You selected: {selected_group}")

    # Show techniques for the selected APT group
    print(f"\nTechniques for {selected_group}:")
    for i, technique in enumerate(apt_groups[selected_group]["techniques"], 1):
        print(f"{i}. {technique['name']} (ID: {technique['id']}, Tactic: {technique['tactic']})")

    # Select techniques to simulate
    selected_techniques = []
    for technique in apt_groups[selected_group]["techniques"]:
        simulate = input(f"Simulate technique {technique['name']}? (y/n): ").lower()
        if simulate == 'y':
            selected_techniques.append(technique)

    # Run simulations for selected techniques
    if not selected_techniques:
        print("[INFO] No techniques selected for simulation. Exiting...")
        return

    print("\n[INFO] Starting simulations...\n")
    for technique in selected_techniques:
        simulate_technique(selected_group, technique)

    # Generate reports
    while True:
        report_format = input("\nGenerate report in text or HTML format? (text/html): ").lower()
        if report_format in ["text", "html"]:
            break
        else:
            print("[ERROR] Invalid input. Please choose 'text' or 'html'.")

    if report_format == "text":
        generate_report_text(selected_group, selected_techniques)
    elif report_format == "html":
        generate_report_html(selected_group, selected_techniques)

if __name__ == "__main__":
    run_simulation()
