import random
import time

def display_splash_screen():
    splash = """
    
   _____  ________               _____   __    __                   __               _________.__              .__           __  .__                             _____  ____         .__       _____           _______  ____  
  /  _  \ \______ \             /  _  \_/  |__/  |______     ____  |  | __          /   _____/|__| _____  __ __|  | _____  _/  |_|__| ____   ____               /  |  |/_   |______  |  |__   /  |  |          \   _  \/_   | 
 /  /_\  \ |    |  \   ______  /  /_\  \   __\   __\__  \  _/ ___\ |  |/ /  ______  \_____  \ |  |/     \|  |  \  | \__  \ \   __\  |/  _ \ /    \    ______   /   |  |_|   |\____ \ |  |  \ /   |  |_  ______ /  /_\  \|   | 
/    |    \|    `   \ /_____/ /    |    \  |  |  |  / __ \_\  \___ |    <  /_____/  /        \|  |  Y Y  \  |  /  |__/ __ \_|  | |  (  <_> )   |  \  /_____/  /    ^   /|   ||  |_> >|   Y  |    ^   / /_____/ \  \_/   \   | 
\____|__  /_______  /         \____|__  /__|  |__| (____  / \___  >|__|_ \         /_______  /|__|__|_|  /____/|____(____  /|__| |__|\____/|___|  /           \____   | |___||   __/ |___|  |____   |           \_____  /___| 
        \/        \/                  \/                \/      \/      \/                 \/          \/                \/                     \/                 |__|      |__|         \/     |__|                 \/      
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
    print("AD_Attack_Surface_Management 41PH4-01\n")

import random
import time

# Define seasons, years, and services for Kerberoasting
seasons = ["Spring", "Summer", "Autumn", "Winter"]
years = list(range(2000, 2025))
services = ["service1", "service2", "service3"]

# Generate season-based passwords for user accounts
passwords = [f"{season}{year}" for season in seasons for year in years]

# Load users from a file
def load_users_from_file(file_name):
    try:
        with open(file_name, "r") as file:
            loaded_users = [line.strip() for line in file.readlines()]
            print(f"[+] Loaded {len(loaded_users)} users from {file_name}")
            return loaded_users
    except FileNotFoundError:
        print(f"[!] Error: File {file_name} not found. Using default users.")
        return ["user1", "user2", "user3", "admin"]

# Simulate Kerberoasting
def kerberoasting():
    print("\n[Kerberoasting] Simulating service ticket request and cracking...")
    for service in services:
        season = random.choice(seasons)
        year = random.choice(years)
        ticket_hash = f"hash_{service}_{season}_{year}_{random.randint(1000,9999)}"
        print(f"Captured ticket hash for {service}: {ticket_hash}")
        time.sleep(1)

# Simulate Password Spraying with No Lockouts
def password_spraying(users):
    print("\n[Password Spraying] Trying season-based passwords...")
    for user in users:
        for password in passwords:
            print(f"Trying {user}:{password}")
            # Simulate authentication attempt (replace with actual logic)
            success = random.choice([True, False])
            if success:
                print(f"[+] Success: {user} logged in with {password}")
                break
            else:
                print(f"[-] Failed for {user}")
        time.sleep(60)  # Add delay between user attempts to prevent lockouts

# Simulate AS-REP Roasting
def asrep_roasting(users):
    print("\n[AS-REP Roasting] Identifying accounts without pre-authentication...")
    for user in users:
        print(f"Checking {user}...")
        success = random.choice([True, False])
        if success:
            ticket_hash = f"asrep_hash_{user}_{random.randint(1000,9999)}"
            print(f"[+] Captured AS-REP hash for {user}: {ticket_hash}")
        else:
            print(f"[-] {user} is secure.")
        time.sleep(1)

# Simulate LDAP Enumeration
def ldap_enumeration():
    print("\n[LDAP Enumeration] Gathering sensitive AD information...")
    objects = ["CN=Users", "CN=Admins", "OU=Finance", "OU=IT"]
    for obj in objects:
        print(f"Enumerating LDAP object: {obj}...")
        sensitive_data = f"Data_{random.randint(100,999)}"
        print(f"Discovered sensitive data: {sensitive_data}")
        time.sleep(1)

# Simulate GPO Analysis
def gpo_analysis():
    print("\n[GPO Analysis] Checking for misconfigurations...")
    gpo_settings = ["Password Policy", "Account Lockout", "Local Admin Rights"]
    for setting in gpo_settings:
        print(f"Checking {setting}...")
        success = random.choice([True, False])
        if success:
            print(f"[!] Vulnerable setting found: {setting}")
        else:
            print(f"[+] {setting} is secure.")
        time.sleep(1)

# Simulate Privilege Escalation
def privilege_escalation():
    print("\n[Privilege Escalation] Attempting to gain elevated access...")
    escalation_methods = ["DLL Injection", "Token Impersonation", "Credential Dumping"]
    for method in escalation_methods:
        print(f"Attempting {method}...")
        success = random.choice([True, False])
        if success:
            print(f"[+] Success with {method}!")
            break
        else:
            print(f"[-] {method} failed.")
        time.sleep(1)

# Main Menu
def main():
    print("Active Directory Attack Simulation Suite")
    print("1. Kerberoasting")
    print("2. Password Spraying")
    print("3. AS-REP Roasting")
    print("4. LDAP Enumeration")
    print("5. GPO Analysis")
    print("6. Privilege Escalation")
    print("7. Run All")
    print("8. Load Users from File")
    
    choice = input("Choose an attack to simulate (1-8): ")

    if choice == '8':
        file_name = input("Enter the user file name (with extension): ")
        users = load_users_from_file(file_name)
        print(f"Loaded users: {users}")
    else:
        users = ["user1", "user2", "user3", "admin"]  # Default users

    if choice == '1':
        kerberoasting()
    elif choice == '2':
        password_spraying(users)
    elif choice == '3':
        asrep_roasting(users)
    elif choice == '4':
        ldap_enumeration()
    elif choice == '5':
        gpo_analysis()
    elif choice == '6':
        privilege_escalation()
    elif choice == '7':
        kerberoasting()
        password_spraying(users)
        asrep_roasting(users)
        ldap_enumeration()
        gpo_analysis()
        privilege_escalation()
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()