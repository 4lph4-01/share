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
from colorama import Fore, Style
import requests

# Splash Screen
def display_splash_screen():
    splash = """
    ##################################################
    #           Penetration Testing Framework       #
    ##################################################
    """
    print(f"{Fore.CYAN}{splash}{Style.RESET_ALL}")

# Display in Columns
def display_in_columns(options, column_count=2):
    max_length = max(len(option) for option in options)
    formatted_options = [
        f"[{index+1}] {option:<{max_length}}" 
        for index, option in enumerate(options)
    ]
    for i in range(0, len(formatted_options), column_count):
        print("    ".join(formatted_options[i:i + column_count]))

# Run OSINT Tools (more_mass.py, Shodan, HackerTarget)
def run_osint_tools():
    print(f"{Fore.CYAN}Running OSINT Tools (More_Mass, Shodan, HackerTarget):{Style.RESET_ALL}")
    
    # Run more_mass.py (as an example, adjust paths if necessary)
    subprocess.run(["python3", "/path/to/more_mass.py"])

    # Shodan Search
    shodan_api_key = "YOUR_SHODAN_API_KEY"
    shodan_query = input("Enter a query for Shodan: ")
    shodan_url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={shodan_query}"
    response = requests.get(shodan_url)
    print(response.json())

    # HackerTarget
    target_domain = input("Enter target domain for HackerTarget: ")
    hacker_target_url = f"https://api.hackertarget.com/hostsearch/?q={target_domain}"
    response = requests.get(hacker_target_url)
    print(response.text)

# Scanning & Enumeration Tools (Nmap, Nikto, etc.)
def run_scanning_tools():
    print(f"{Fore.CYAN}Running Scanning & Enumeration Tools (Nmap, Nikto):{Style.RESET_ALL}")
    tools = [
        "Run Nmap Scan",
        "Run Nikto Scan",
        "Run DNS Lookup",
        "Back to Main Menu"
    ]
    display_in_columns(tools)

    choice = input(f"{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        target_ip = input("Enter target IP: ")
        subprocess.run(["nmap", "-sS", target_ip])
    elif choice == "2":
        target_ip = input("Enter target IP: ")
        subprocess.run(["nikto", "-h", target_ip])
    elif choice == "3":
        target_domain = input("Enter target domain: ")
        subprocess.run(["dig", target_domain])
    elif choice == "4":
        main_menu()
    else:
        print(f"{Fore.RED}Invalid choice, returning to Scanning Tools Menu.{Style.RESET_ALL}")
        run_scanning_tools()

# Gaining Access Menu (Metasploit, Hydra, MSFVenom)
def gaining_access_menu():
    print(f"{Fore.CYAN}Gaining Access Tools:{Style.RESET_ALL}")
    tools = [
        "Run MSFVenom",
        "Run Metasploit",
        "Run Hydra Brute Force",
        "Back to Main Menu"
    ]
    display_in_columns(tools)

    choice = input(f"{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        subprocess.run(["msfvenom", "-p", "linux/x86/shell_reverse_tcp", "-f", "elf", "-o", "reverse_shell.elf"])
    elif choice == "2":
        subprocess.run(["msfconsole"])
    elif choice == "3":
        target_ip = input("Enter target IP for Hydra: ")
        subprocess.run(["hydra", "-l", "admin", "-P", "/path/to/wordlist.txt", target_ip, "http-get"])
    elif choice == "4":
        main_menu()
    else:
        print(f"{Fore.RED}Invalid choice, returning to Gaining Access Menu.{Style.RESET_ALL}")
        gaining_access_menu()

# Setup Proxies (Example)
def setup_proxies():
    print(f"{Fore.CYAN}Setting up Proxies:{Style.RESET_ALL}")
    # Placeholder for proxy setup tools
    print("Proxies have been set up!")

# Maintaining Access (Example)
def maintain_access():
    print(f"{Fore.CYAN}Maintaining Access:{Style.RESET_ALL}")
    # Placeholder for maintaining access tools
    print("Access has been maintained!")

# Covering Tracks (Example)
def cover_tracks():
    print(f"{Fore.CYAN}Covering Tracks:{Style.RESET_ALL}")
    # Placeholder for covering tracks tools
    print("Tracks have been covered!")

# Report Generation (Placeholder)
def generate_report():
    print(f"{Fore.CYAN}Generating Report:{Style.RESET_ALL}")
    # Placeholder for report generation (e.g., write output to file)
    with open("penetration_test_report.txt", "w") as report:
        report.write("Penetration Test Report\n")
        report.write("========================\n")
        # Add tool outputs here
        report.write("OSINT Results: More_Mass, Shodan, HackerTarget...\n")
    print("Report has been generated!")

# Main Menu
def main_menu():
    display_splash_screen()
    options = [
        "Penetration Test Methodology",
        "Reconnaissance & Information Gathering (OSINT)",
        "Scanning & Enumeration",
        "Gaining Access Tools",
        "Setup Proxies",
        "Maintaining Access",
        "Covering Tracks",
        "Generate Report",
        "Exit"
    ]
    display_in_columns(options)

    choice = input(f"{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    try:
        if choice == "1":
            print("Penetration Test Methodology")
        elif choice == "2":
            run_osint_tools()
        elif choice == "3":
            run_scanning_tools()
        elif choice == "4":
            gaining_access_menu()
        elif choice == "5":
            setup_proxies()
        elif choice == "6":
            maintain_access()
        elif choice == "7":
            cover_tracks()
        elif choice == "8":
            generate_report()
        elif choice == "9":
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
