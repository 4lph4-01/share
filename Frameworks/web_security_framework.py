######################################################################################################################################################################################################################
# Python script for possible vulnerabilities in a web application, and does not constitute or replace a robust vulnerability scanner. Note: Be mindful of the scope of work, & rules of engagement, script also requires BeautifulSoup Ref:https://beautiful-soup-4.readthedocs.io/en/latest/. .
# python web_security_framework.py. Requires a linux virtual environment for older python version funtionality, pip restrictions for external dependancies, and reducing conflicts. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# Replace teaget_url with the specific endpoints you want to test for each vulnerability. Replace "http://your_base_url" with the base URL of the application you're testing
######################################################################################################################################################################################################################


import random
import string
from datetime import datetime
import os
import requests
from bs4 import BeautifulSoup

    
# Banner
def print_banner():
    banner = r"""
    
__      __        ___.             _____                  .__   .__                  __  .__                       _________                           .__   __                ___________                                                  __                  _____  ______________  ___ ___    _____           _______  ____ 
/  \    /  \  ____ \_ |__          /  _  \ ______  ______  |  |  |__|  ____  _____  _/  |_|__| ____   ____         /   _____/ ____   ____   __ _________|__|_/  |_  ___.__.     \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
\   \/\/   /_/ __ \ | __ \        /  /_\  \\____ \ \____ \ |  |  |  |_/ ___\ \__  \ \   __\  |/  _ \ /    \        \_____  \_/ __ \_/ ___\ |  |  \_  __ \  |\   __\<   |  |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 \        / \  ___/ | \_\ \      /    |    \  |_> >|  |_> >|  |__|  |\  \___  / __ \_|  | |  (  <_> )   |  \       /        \  ___/\  \___ |  |  /|  | \/  | |  |   \___  |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
  \__/\  /   \___  >|___  /______\____|__  /   __/ |   __/ |____/|__| \___  >(____  /|__| |__|\____/|___|  /______/_______  /\___  >\___  >|____/ |__|  |__| |__|   / ____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___||____|    \___|_  /\____   |           \_____  /___|
       \/        \/     \//_____/        \/|__|    |__|                   \/      \/                     \//_____/        \/     \/     \/                          \/    /_____/    \/                \/       \/     \/                        \/                |__|                      \/      |__|                 \/     

                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/
                                 /\      {====}     )___(
                      (\=,      //\\      )__(     /_____\
      __    |'-'-'|  //  .\    (    )    /____\     |   |
     /  \   |_____| (( \_  \    )__(      |  |      |   |
     \__/    |===|   ))  \_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)

    """
    print(banner)


# Function to log test results to a file
def log_result(test_name, result, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {test_name}: {result}\nDetails: {details}\n"
    
    with open("penetration_testing_report.txt", "a") as log_file:
        log_file.write(log_entry)

# Function to log test results to an HTML report
def log_result_html(test_name, result, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_entry = f"""
    <tr>
        <td>{timestamp}</td>
        <td>{test_name}</td>
        <td>{result}</td>
        <td>{details}</td>
    </tr>
    """
    if not os.path.exists("penetration_testing_report.html"):
        with open("penetration_testing_report.html", "w") as html_file:
            html_file.write("""
            <html>
                <head><title>Penetration Testing Report</title></head>
                <body>
                    <h1>Penetration Testing Report</h1>
                    <table border="1">
                        <tr><th>Timestamp</th><th>Test</th><th>Result</th><th>Details</th></tr>
            """)

    with open("penetration_testing_report.html", "a") as html_file:
        html_file.write(report_entry)

    with open("penetration_testing_report.html", "a") as html_file:
        html_file.write("""
                    </table>
                </body>
            </html>
            """)

# Function to simulate crawling (stub function, needs implementation)
def crawl_website(url):
    print(f"Crawling website: {url}")
    # Add your crawling logic here
    log_result("Crawl Website", "Success", f"Crawled {url} and extracted forms.")

# Function to simulate brute force testing (stub function, needs implementation)
def brute_force_test(url):
    print(f"Running brute force test on: {url}")
    # Add brute force logic here
    log_result("Brute Force Test", "Success", f"Brute forced {url}.")

# --- New Vulnerability Tests ---
# RCE Test (Remote Code Execution)
def rce_test(url):
    print(f"Testing for Remote Code Execution (RCE) on: {url}")
    # Add RCE testing logic here
    payload = {"cmd": "whoami"}
    response = requests.post(url, data=payload)
    if "root" in response.text or "admin" in response.text:
        log_result("RCE Test", "Vulnerable", f"RCE vulnerability detected on {url}. Command output: {response.text}")
    else:
        log_result("RCE Test", "Not Vulnerable", f"No RCE vulnerability detected on {url}.")

# LDAP Injection Test
def ldap_injection_test(url):
    print(f"Testing for LDAP Injection on: {url}")
    payload = {"username": "admin", "password": "' OR 1=1"}
    response = requests.post(url, data=payload)
    if "Authentication failed" not in response.text:
        log_result("LDAP Injection Test", "Vulnerable", f"LDAP Injection vulnerability detected on {url}. Response: {response.text}")
    else:
        log_result("LDAP Injection Test", "Not Vulnerable", f"No LDAP Injection vulnerability detected on {url}.")

# Path Traversal Test
def path_traversal_test(url):
    print(f"Testing for Path Traversal on: {url}")
    payload = {"file": "../../etc/passwd"}
    response = requests.get(url, params=payload)
    if "root:" in response.text:
        log_result("Path Traversal Test", "Vulnerable", f"Path Traversal vulnerability detected on {url}. Response: {response.text}")
    else:
        log_result("Path Traversal Test", "Not Vulnerable", f"No Path Traversal vulnerability detected on {url}.")

# --- Payload Crafting (for specific vulnerabilities) ---
def craft_sql_injection_payload():
    # Craft common SQL injection payloads
    payloads = [
        "' OR 1=1 --",
        "' UNION SELECT NULL, username, password FROM users --",
        # "'; DROP TABLE users --"  # Commented out to avoid accidental data loss
    ]
    return random.choice(payloads)

# --- Exploit Execution (Optional) ---
def execute_exploit(url, exploit_type):
    if exploit_type == "RCE":
        print(f"Executing Remote Code Execution exploit on {url}")
        # Add RCE exploit logic here (ensure ethical use)
        payload = {"cmd": "whoami"}
        response = requests.post(url, data=payload)
        log_result("RCE Exploit", "Executed", f"Command output: {response.text}")
    # Add more exploits like LDAP injection, XSS, etc., with a similar structure

# --- Menu System ---
def print_main_menu():
    options = [
        "[1] Crawl Website and Extract Forms", "[2] Brute Force Test (Optional)", 
        "[3] RCE Test", "[4] LDAP Injection Test", "[5] Path Traversal Test", 
        "[6] SQL Injection Test", "[7] Execute Exploit", "[8] Exit"
    ]
    
    # Display options in a column-like structure
    print("=" * 30)
    print("Advanced Web Penetration Testing Framework")
    print("=" * 30)
    for i in range(0, len(options), 2):
        print(f"{options[i]:<40} {options[i+1] if i+1 < len(options) else ''}")
    print("=" * 30)

# Function to get user input for form selection
def get_user_input():
    try:
        return int(input("Enter your choice (1-8): "))
    except ValueError:
        print("Invalid input, please enter a number between 1 and 8.")
        return get_user_input()

# Main function to manage the user interface
def main():
    while True:
        try:
            print_main_menu()
            choice = get_user_input()
            if choice == 1:
                url = input("Enter the URL of the website to crawl: ")
                crawl_website(url)
            elif choice == 2:
                url = input("Enter the URL for brute force test: ")
                brute_force_test(url)
            elif choice == 3:
                url = input("Enter the URL for RCE Test: ")
                rce_test(url)
            elif choice == 4:
                url = input("Enter the URL for LDAP Injection Test: ")
                ldap_injection_test(url)
            elif choice == 5:
                url = input("Enter the URL for Path Traversal Test: ")
                path_traversal_test(url)
            elif choice == 6:
                payload = craft_sql_injection_payload()
                print(f"Crafted SQL Injection Payload: {payload}")
                # Implement SQL Injection test with crafted payload here
            elif choice == 7:
                url = input("Enter the URL for Exploit Execution: ")
                exploit_type = input("Enter exploit type (RCE, LDAP, XSS, etc.): ")
                execute_exploit(url, exploit_type)
            elif choice == 8:
                print("Exiting...")
                break
            else:
                print("Invalid option, please select a valid choice.")
        except KeyboardInterrupt:
            print("\nExiting on user request.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    print_banner()
    main()
