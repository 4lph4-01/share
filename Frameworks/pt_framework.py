import subprocess
import sys
import os
import asyncio
import aiohttp
import json
from colorama import Fore, Style

# Function to check if a command exists
def check_command(command):
    try:
        subprocess.run([command, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

# Function to install missing tools (this will be basic for illustration)
def install_tool(tool_name, install_command):
    print(f"{Fore.TEAL}Installing {tool_name}...\n{Style.RESET_ALL}")
    subprocess.run(install_command, shell=True)

# Function to display the main menu (Options in columns)
def display_menu():
    print(f"{Fore.TEAL}\n[1] MSFVenom    [2] Metasploit")
    print("[3] Veil        [4] Web Application Security Framework")
    print("[5] Exploit API [6] Report & Save Results")
    print("[7] Exit{Style.RESET_ALL}")

# Function to install tools if needed
def install_tools():
    tools = [
        {"name": "MSFVenom", "command": "msfvenom", "install_cmd": "sudo apt-get install metasploit-framework"},
        {"name": "Metasploit", "command": "msfconsole", "install_cmd": "sudo apt-get install metasploit-framework"},
        {"name": "Veil", "command": "veil", "install_cmd": "git clone https://github.com/Veil-Framework/Veil.git; cd Veil; sudo ./install.sh"}
    ]
    
    for tool in tools:
        if not check_command(tool["command"]):
            print(f"{Fore.RED}{tool['name']} is not installed.{Style.RESET_ALL}")
            install_choice = input(f"{Fore.YELLOW}Would you like to install {tool['name']}? (y/n): {Style.RESET_ALL}")
            if install_choice.lower() == 'y':
                install_tool(tool['name'], tool["install_cmd"])

# Function to display the splash screen
def display_splash_screen():
    splash = """
    \033[36m
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
   
    print(f"{Fore.TEAL}{splash}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Web_Application_Security_Framework 41PH4-01{Style.RESET_ALL}")

# Function to handle API Key functionality
def handle_api_keys():
    print("\n[1] Sign Up for API Key")
    print("[2] Enter API Key")
    print("[3] Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        print("Visit the API provider's website to sign up for an API key.")
    elif choice == "2":
        api_key = input("Enter your API Key: ")
        save_api_key(api_key)
    elif choice == "3":
        print("Returning to main menu.")

# Save the API Key to a file
def save_api_key(api_key):
    with open('api_key.txt', 'w') as file:
        file.write(api_key)
    print(f"{Fore.GREEN}API Key saved for future use.{Style.RESET_ALL}")

# Function to display the exploit API menu (Options in columns)
def display_exploit_api_menu():
    print("\n[1] Get Exploits from Searchsploit    [2] Cross-Reference with Available Exploits")
    print("[3] Exit to Main Menu")

# Function to simulate fetching exploits from Searchsploit
async def get_exploits_from_searchsploit():
    print(f"{Fore.CYAN}Fetching exploits from Searchsploit...{Style.RESET_ALL}")
    # Placeholder code for fetching from Searchsploit

# Function to display a simple process bar
def process_bar(task_name):
    print(f"\n{Fore.GREEN}Installing {task_name}...{Style.RESET_ALL}")
    for i in range(0, 101, 10):
        print(f"{Fore.YELLOW}[{'#' * (i // 10)}{' ' * ((100 - i) // 10)}] {i}%{Style.RESET_ALL}")
        time.sleep(0.5)
    print(f"{Fore.GREEN}{task_name} installation complete!{Style.RESET_ALL}")

# Main function to control the script
def main():
    display_splash_screen()
    
    # Install tools if needed
    install_tools()

    while True:
        display_menu()
        choice = input(f"{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
        
        if choice == "1":
            print(f"{Fore.TEAL}Launching MSFVenom...{Style.RESET_ALL}")
            subprocess.run(["msfvenom"])
        elif choice == "2":
            print(f"{Fore.TEAL}Launching Metasploit...{Style.RESET_ALL}")
            subprocess.run(["msfconsole"])
        elif choice == "3":
            print(f"{Fore.TEAL}Launching Veil...{Style.RESET_ALL}")
            subprocess.run(["veil"])
        elif choice == "4":
            print(f"{Fore.TEAL}Launching Web Application Security Framework...{Style.RESET_ALL}")
            # Call your framework's main function here
        elif choice == "5":
            while True:
                display_exploit_api_menu()
                api_choice = input(f"{Fore.YELLOW}Enter your choice: {Style.RESET_ALL}")
                
                if api_choice == "1":
                    print(f"{Fore.CYAN}Fetching exploits from Searchsploit...{Style.RESET_ALL}")
                    asyncio.run(get_exploits_from_searchsploit())
                elif api_choice == "2":
                    print(f"{Fore.CYAN}Cross-referencing with available exploits...{Style.RESET_ALL}")
                    # Placeholder for cross-referencing functionality
                elif api_choice == "3":
                    break
                else:
                    print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")
        elif choice == "6":
            print(f"{Fore.MAGENTA}Generating Report...{Style.RESET_ALL}")
            # Placeholder for reporting functionality
        elif choice == "7":
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice, please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
