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

# SSH Port Forwarding
def setup_ssh_port_forwarding():
    print(f"\n{Fore.YELLOW}SSH Port Forwarding:{Style.RESET_ALL}")
    local_port = input("Enter local port to forward: ")
    target_host = input("Enter target host (e.g., 10.0.0.1): ")
    target_port = input("Enter target port (e.g., 80): ")
    try:
        command = f"ssh -L {local_port}:{target_host}:{target_port} user@remote_host"
        print(f"Executing: {command}")
        subprocess.run(command, shell=True, check=True)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

# MSF Port Forwarding
def setup_msf_port_forwarding():
    print(f"\n{Fore.YELLOW}MSF Port Forwarding:{Style.RESET_ALL}")
    print("To setup port forwarding in Metasploit, use:")
    print("1. Use the 'portfwd' command.")
    print("   Example: portfwd add -l [local_port] -r [remote_host] -p [remote_port]")
    input(f"{Fore.GREEN}Press Enter to return to menu...{Style.RESET_ALL}")

# Main Menu
def display_main_menu():
    print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
    options = [
        "Reconnaissance Tools", 
        "Scanning & Enumeration", 
        "Exploitation Tools", 
        "Proxies", 
        "Gaining Access", 
        "Maintaining Access", 
        "Covering Tracks", 
        "Reports & Results", 
        "Exit"
    ]
    display_in_columns(options, column_count=3)

# Maintaining Access Menu
def maintaining_access_menu():
    print(f"\n{Fore.CYAN}Maintaining Access:{Style.RESET_ALL}")
    options = [
        "Set up Backdoors",
        "Install Persistent Agents",
        "Remote Access Tools",
        "Setup SSH Port Forwarding",
        "Setup MSF Port Forwarding",
        "Return to Main Menu"
    ]
    display_in_columns(options, column_count=2)

    choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
    if choice == "1":
        print("Backdoors functionality coming soon...")
    elif choice == "2":
        print("Persistent agents functionality coming soon...")
    elif choice == "3":
        print("Remote access tools functionality coming soon...")
    elif choice == "4":
        setup_ssh_port_forwarding()
    elif choice == "5":
        setup_msf_port_forwarding()
    elif choice == "6":
        return
    else:
        print(f"{Fore.RED}Invalid choice, returning to main menu.{Style.RESET_ALL}")

# Main Function
def main():
    display_splash_screen()

    while True:
        display_main_menu()
        choice = input(f"\n{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
        
        if choice == "1":
            print("Reconnaissance Tools menu coming soon...")
        elif choice == "2":
            print("Scanning & Enumeration menu coming soon...")
        elif choice == "3":
            print("Exploitation Tools menu coming soon...")
        elif choice == "4":
            print("Proxies menu coming soon...")
        elif choice == "5":
            print("Gaining Access menu coming soon...")
        elif choice == "6":
            maintaining_access_menu()
        elif choice == "7":
            print("Covering Tracks menu coming soon...")
        elif choice == "8":
            print("Reports & Results menu coming soon...")
        elif choice == "9":
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
