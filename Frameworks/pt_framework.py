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
import os
import time
from colorama import Fore, Style

# Splash Screen
def display_splash_screen():
    splash = """
    
_____________________  ___________                                                  __                  _____  ______________  ___ ___    _____           _______  ____ 
\______   \__    ___/  \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
 |     ___/ |    |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |    |     |    |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
 |____|     |____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___||____|    \___|_  /\____   |           \_____  /___|
                 /_____/    \/                \/       \/     \/                        \/                |__|                      \/      |__|                 \/     

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

# Columnar Display Helper Function
def display_in_columns(options, column_count=2):
    max_length = max(len(option) for option in options)
    formatted_options = [
        f"[{index+1}] {option:<{max_length}}" 
        for index, option in enumerate(options)
    ]
    for i in range(0, len(formatted_options), column_count):
        print("    ".join(formatted_options[i:i + column_count]))

# Tool Functions
def launch_tool(command):
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Command not found - {command[0]}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

def launch_msfvenom():
    print(f"{Fore.YELLOW}Launching MSFVenom...{Style.RESET_ALL}")
    launch_tool(["msfvenom"])

def setup_ssh_port_forwarding():
    print(f"{Fore.YELLOW}Setting up SSH port forwarding...{Style.RESET_ALL}")
    source_port = input("Enter source port (e.g., 8080): ")
    target_host = input("Enter target host (e.g., 192.168.1.100): ")
    target_port = input("Enter target port (e.g., 80): ")
    remote_user = input("Enter remote username (e.g., user): ")
    remote_host = input("Enter remote host (e.g., example.com): ")
    try:
        command = [
            "ssh",
            "-L", f"{source_port}:{target_host}:{target_port}",
            f"{remote_user}@{remote_host}"
        ]
        print(f"{Fore.GREEN}Executing: {' '.join(command)}{Style.RESET_ALL}")
        subprocess.run(command, check=True)
    except Exception as e:
        print(f"{Fore.RED}Failed to set up SSH port forwarding: {e}{Style.RESET_ALL}")

def setup_msf_port_forwarding():
    print(f"{Fore.YELLOW}Setting up MSF port forwarding...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}To set up port forwarding in Metasploit, run the following:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}portfwd add -l <local_port> -p <remote_port> -r <remote_host>{Style.RESET_ALL}")

# Sub-menus
def proxies_menu():
    print(f"\n{Fore.CYAN}Proxies:{Style.RESET_ALL}")
    options = [
        "Configure Proxychains",
        "Test Proxychains Setup",
        "Setup Tor Network",
        "Setup MSF Port Forwarding",
        "Setup SSH Port Forwarding",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        launch_tool(["proxychains", "firefox"])
    elif choice == "2":
        launch_tool(["proxychains", "curl", "http://ipinfo.io"])
    elif choice == "3":
        launch_tool(["tor"])
    elif choice == "4":
        setup_msf_port_forwarding()
    elif choice == "5":
        setup_ssh_port_forwarding()
    elif choice == "6":
        return
    else:
        print(f"{Fore.RED}Invalid choice, returning to main menu.{Style.RESET_ALL}")

# Main Menu
def display_main_menu():
    print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
    options = [
        "Exploitation Tools", 
        "Reconnaissance Tools", 
        "Scanning & Enumeration", 
        "Proxies", 
        "Gaining Access", 
        "Maintaining Access", 
        "Covering Tracks", 
        "Reports & Results", 
        "Exit"
    ]
    display_in_columns(options, column_count=3)

# Main Function
def main():
    display_splash_screen()

    while True:
        display_main_menu()
        try:
            choice = int(input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}"))
        except ValueError:
            print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
            continue

        if choice == 1:
            launch_msfvenom()
        elif choice == 4:
            proxies_menu()
        elif choice == 9:
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
