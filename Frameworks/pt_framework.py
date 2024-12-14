######################################################################################################################################################################################################################
# Python script Penetration Testing & Ethical Hacking Framework, Note: Be mindful of the scope of work, & rules of engagement. Ensure more_mass.py is in the same working directory or absolutepath for integration.
# https://github.com/4lph4-01/share/blob/main/Automation%20-%20Information%20Gathering/more_mass.py 
# sudo python3 pt_framework.py. Optional API's, and subdomain bruteforce. 
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
import os
import shutil
import requests
from pathlib import Path
from colorama import Fore, Style


def display_splash_screen():
    splash = r"""

 _____________________  ___________                                                  __                  _____  ____.____   __________  ___ ___    _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
                 /_____/    \/                \/       \/     \/                        \/                |__|             \/               \/      |__|                 \/     

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
    print(f"{Fore.CYAN}{splash}{Style.RESET_ALL}")


# Global Log File
LOG_FILE = "pentest_log.txt"

# Write Logs
def write_log(tool_name, output):
    with open(LOG_FILE, "a") as log:
        log.write(f"\n--- {tool_name} Output ---\n")
        log.write(output)
        log.write("\n-------------------------\n")


# Tool Execution with Output Logging
def execute_tool(command, tool_name):
    print(f"{Fore.YELLOW}Running: {' '.join(command)}{Style.RESET_ALL}")
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        captured_output = []  # To collect output for logging

        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(f"{Fore.GREEN}{output.strip()}{Style.RESET_ALL}")
                captured_output.append(output)

        _, errors = process.communicate()
        if errors:
            error_message = f"{Fore.RED}Errors: {errors.strip()}{Style.RESET_ALL}"
            print(error_message)
            captured_output.append(f"Errors: {errors.strip()}\n")

        # Save to log
        write_log(tool_name, "".join(captured_output))
    except Exception as e:
        error_message = f"{Fore.RED}Failed to run {tool_name}: {e}{Style.RESET_ALL}"
        print(error_message)
        write_log(tool_name, error_message)


# Tools Integration
def metasploit():
    print(f"{Fore.CYAN}Launching Metasploit...{Style.RESET_ALL}")
    execute_tool(["msfconsole"], "Metasploit")


def veil():
    print(f"{Fore.CYAN}Launching Veil Framework...{Style.RESET_ALL}")
    execute_tool(["veil"], "Veil Framework")


def empire():
    print(f"{Fore.CYAN}Launching Empire Framework...{Style.RESET_ALL}")
    execute_tool(["python3", "/path/to/Empire/empire"], "Empire Framework")


# Report Generation
def generate_report():
    if not os.path.exists(LOG_FILE):
        print(f"{Fore.RED}No log file found. Run some tools first.{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}Generating report...{Style.RESET_ALL}")
    with open(LOG_FILE, "r") as log:
        report = log.read()

    report_file = "pentest_report.txt"
    with open(report_file, "w") as report_output:
        report_output.write(report)

    print(f"{Fore.GREEN}Report saved to {report_file}{Style.RESET_ALL}")


# Gaining Access
def gaining_access():
    print(f"{Fore.CYAN}Gaining Access Options{Style.RESET_ALL}")
    options = [
        "Launch Metasploit",
        "Launch Veil Framework",
        "Launch Empire Framework",
        "Back to Main Menu"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")

    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        metasploit()
    elif choice == "2":
        veil()
    elif choice == "3":
        empire()
    else:
        main_menu()


# Main Menu
def main_menu():
    display_splash_screen()
    tools = ['nmap', 'nikto', 'msfconsole', 'veil', 'python3']  # Include required tools
    for tool in tools:
        if shutil.which(tool) is None:
            print(f"{Fore.RED}{tool} is not installed.{Style.RESET_ALL}")
            choice = input(f"Do you want to install {tool}? (y/n): ").lower()
            if choice == "y":
                install_tool(tool)

    options = [
        "Reconnaissance & Information Gathering",
        "Scanning & Enumeration",
        "Gaining Access",
        "Maintaining Access",
        "Covering Tracks",
        "Generate Report",
        "Exit"
    ]
    for idx, option in enumerate(options, start=1):
        print(f"[{idx}] {option}")

    choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
    if choice == "1":
        reconnaissance()
    elif choice == "2":
        scanning()
    elif choice == "3":
        gaining_access()
    elif choice == "4":
        maintaining_access()
    elif choice == "5":
        covering_tracks()
    elif choice == "6":
        generate_report()
    elif choice == "7":
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    else:
        main_menu()


if __name__ == "__main__":
    # Start with a fresh log file
    open(LOG_FILE, "w").close()
    main_menu()
