import subprocess
import sys
import os
import asyncio
import aiohttp
import json

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
    print(splash)
    print("\033[36mWeb_Application_Security_Framework 41PH4-01\n\033[0m")

# Function to display the menu with numbered options in columns
def display_menu():
    print("\033[36mPlease select an option:\033[0m")
    print("\033[36m1)\033[0m Install Tools    \033[36m2)\033[0m Exploit Search    \033[36m3)\033[0m Vulnerability Check  ")
    print("\033[36m4)\033[0m Run Metasploit    \033[36m5)\033[0m Run MSFVenom     \033[36m6)\033[0m Run Veil Framework  ")
    print("\033[36m7)\033[0m Check Infrastructure   \033[36m8)\033[0m API Integrations   \033[36m9)\033[0m Report Generation  ")
    print("\033[36m10)\033[0m Exit")
    print("\033[36mSelect a number (1-10): \033[0m")

# Function to install necessary tools
def install_tools():
    print("\033[36mInstalling tools...\033[0m")
    # Add installation logic for tools like MSFVenom, Metasploit, Veil etc.
    subprocess.run(["sudo", "apt-get", "install", "metasploit-framework", "veil", "msfvenom", "-y"])

# Function to handle API integration
def handle_api_integration():
    print("\033[36mPlease enter your API key (e.g., for Shodan, Censys, etc.): \033[0m")
    api_key = input()
    
    save_api_key = input("\033[36mDo you want to save the API key for future use? (y/n): \033[0m")
    if save_api_key.lower() == "y":
        with open("api_key.txt", "w") as f:
            f.write(api_key)
        print("\033[36mAPI key saved.\033[0m")
    else:
        print("\033[36mAPI key not saved.\033[0m")

# Function to check for infrastructure vulnerabilities
def check_infrastructure_vulnerabilities():
    print("\033[36mChecking infrastructure vulnerabilities...\033[0m")
    # Placeholder for actual vulnerability scanning logic.
    subprocess.run(["nmap", "-sV", "example.com"])

# Function to generate reports
def generate_report():
    print("\033[36mSelect a reporting option:\033[0m")
    print("\033[36m1)\033[0m Save Exploit Search Results  \033[36m2)\033[0m Save Vulnerability Check Results")
    print("\033[36m3)\033[0m Generate Detailed Report (HTML/PDF)  \033[36m4)\033[0m Back")
    
    choice = input("\033[36mSelect a number (1-4): \033[0m")
    if choice == "1":
        print("\033[36mSaving Exploit Search Results...\033[0m")
    elif choice == "2":
        print("\033[36mSaving Vulnerability Check Results...\033[0m")
    elif choice == "3":
        print("\033[36mGenerating Detailed Report...\033[0m")
    elif choice == "4":
        return
    else:
        print("\033[36mInvalid choice. Please try again.\033[0m")

# Main function to handle user inputs
def main():
    display_splash_screen()

    while True:
        display_menu()

        choice = input()

        if choice == "1":
            install_tools()
        elif choice == "2":
            print("\033[36mSearching for exploits...\033[0m")
        elif choice == "3":
            print("\033[36mChecking for vulnerabilities...\033[0m")
        elif choice == "4":
            print("\033[36mRunning Metasploit...\033[0m")
        elif choice == "5":
            print("\033[36mRunning MSFVenom...\033[0m")
        elif choice == "6":
            print("\033[36mRunning Veil Framework...\033[0m")
        elif choice == "7":
            check_infrastructure_vulnerabilities()
        elif choice == "8":
            handle_api_integration()
        elif choice == "9":
            generate_report()
        elif choice == "10":
            print("\033[36mExiting PT Framework...\033[0m")
            break
        else:
            print("\033[36mInvalid selection, please try again.\033[0m")

if __name__ == "__main__":
    main()
