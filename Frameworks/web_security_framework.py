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

import csv
import requests
import threading
from urllib.parse import urljoin, urlparse
from datetime import datetime
from colorama import Fore, Style
from bs4 import BeautifulSoup
import re

# Global Settings
TARGET_URL = "http://example.com"  # Replace with actual target
SESSION = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

# Report File
REPORT_FILE = 'vulnerability_report.csv'

# Allowed domains and paths
ALLOWED_DOMAINS = ["example.com", "sub.example.com"]  # Add domains or subdomains to crawl
ALLOWED_PATHS = ["/admin/", "/products/"]  # Add allowed paths to crawl

# Initialize CSV Report with headers
def initialize_report():
    with open(REPORT_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp', 'Test', 'Outcome', 'Details'])

# Log Results into the CSV file
def log_report(test_name, outcome, details=""):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(REPORT_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, test_name, outcome, details])

# Banner
def display_splash_screen():
    splash = """
    
__      __        ___.                                  _________                           .__   __                ___________                                                  __                  _____  ____.____   __________  ___ ___    _____           _______  ____ 
/  \    /  \  ____ \_ |__ _____   ______  ______        /   _____/ ____   ____   __ _________|__|_/  |_  ___.__.     \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
\   \/\/   /_/ __ \ | __ \\__  \  \____ \ \____ \       \_____  \_/ __ \_/ ___\ |  |  \_  __ \  |\   __\<   |  |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 \        / \  ___/ | \_\ \/ __ \_|  |_> >|  |_> >      /        \  ___/\  \___ |  |  /|  | \/  | |  |   \___  |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
  \__/\  /   \___  >|___  (____  /|   __/ |   __/______/_______  /\___  >\___  >|____/ |__|  |__| |__|   / ____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
       \/        \/     \/     \/ |__|    |__|  /_____/        \/     \/     \/                          \/    /_____/    \/                \/       \/     \/                        \/                |__|             \/               \/      |__|                 \/     

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
   (______)(_______)(_______)(________)(________)(_________)

    """
    print(splash)
    print("Web_Application_Security_Framework 41PH4-01\n")

# Columnar Display Helper Function (no row limit)
def display_in_columns(options):
    max_length = max(len(option) for option in options)
    formatted_options = [
        f"[{index+1}] {option:<{max_length}}" 
        for index, option in enumerate(options)
    ]
    print("    ".join(formatted_options))

# Extract all links from a page
def extract_links(url, page_content):
    soup = BeautifulSoup(page_content, 'html.parser')
    links = set()
    for anchor in soup.find_all('a', href=True):
        link = anchor['href']
        link = urljoin(url, link)  # Ensure absolute URL
        links.add(link)
    return links

# Function to crawl the site and ensure links are within the allowed domains and paths
def crawl_site(url, visited=None, depth=0, max_depth=3):
    if visited is None:
        visited = set()

    # If we've reached the max depth, stop
    if depth > max_depth:
        return visited

    if url in visited:
        return visited

    visited.add(url)
    print(f"Crawling: {url}")

    try:
        response = SESSION.get(url, headers=HEADERS)
        if response.status_code == 200:
            links = extract_links(url, response.text)
            for link in links:
                # Check if the link fits within allowed domains and paths
                if any(domain in link for domain in ALLOWED_DOMAINS) and any(path in link for path in ALLOWED_PATHS):
                    # Recursively crawl discovered links
                    visited.update(crawl_site(link, visited, depth + 1, max_depth))
                else:
                    print(f"Skipping link (out of scope): {link}")
    except requests.RequestException as e:
        print(f"Error crawling {url}: {e}")

    return visited

# Crawl and collect links in the target site
def discover_links():
    print(f"Starting to crawl {TARGET_URL}")
    links = crawl_site(TARGET_URL)

    print(f"Found {len(links)} links:")
    for link in links:
        print(link)
    return links

# Attack Modules

def test_sql_injection(url, param_name):
    payload = "' OR 1=1 --"
    data = {param_name: payload}
    response = SESSION.post(url, data=data, headers=HEADERS)

    if "error" in response.text or "syntax" in response.text:
        log_report("SQL Injection", "Vulnerable", "SQL Injection vulnerability detected.")
        return "SQL Injection: Vulnerable"
    else:
        log_report("SQL Injection", "Not Vulnerable", "No SQL Injection detected.")
        return "SQL Injection: Not Vulnerable"

def test_brute_force_login(url, username_param, password_param):
    common_passwords = ["123456", "password", "admin"]
    for password in common_passwords:
        data = {username_param: "admin", password_param: password}
        response = SESSION.post(url, data=data, headers=HEADERS)

        if "success" in response.text:  # Adjust based on the login success indicator
            log_report("Brute Force", "Vulnerable", f"Login bypass with password: {password}")
            return f"Brute Force: Vulnerable, Bypass with {password}"
        else:
            log_report("Brute Force", "Not Vulnerable", "No password bypass detected.")
            return "Brute Force: Not Vulnerable"

def test_reflected_xss(url, param_name):
    payload = "<script>alert('XSS')</script>"
    data = {param_name: payload}
    response = SESSION.post(url, data=data, headers=HEADERS)

    if payload in response.text:
        log_report("Reflected XSS", "Vulnerable", "Reflected XSS vulnerability detected.")
        return "Reflected XSS: Vulnerable"
    else:
        log_report("Reflected XSS", "Not Vulnerable", "No Reflected XSS detected.")
        return "Reflected XSS: Not Vulnerable"

def test_access_control(url, param_name):
    response = SESSION.get(url + f"?{param_name}=admin", headers=HEADERS)
    if "admin page" in response.text:  # Adjust based on the access control mechanism
        log_report("Access Control", "Vulnerable", "Access Control vulnerability detected.")
        return "Access Control: Vulnerable"
    else:
        log_report("Access Control", "Not Vulnerable", "No access control issues detected.")
        return "Access Control: Not Vulnerable"

# Main Execution Flow
def main():
    display_splash_screen()
    initialize_report()

    options = [
        "Crawl site and discover links",
        "Test SQL Injection",
        "Test Brute Force Login",
        "Test Reflected XSS",
        "Test Access Control",
        "Exit"
    ]
    
    while True:
        display_in_columns(options)
        selection = input(f"Select an option (1-{len(options)}): ")

        try:
            selection = int(selection)
            if selection == 1:
                discover_links()
            elif selection == 2:
                url = input("Enter URL for SQL Injection test: ")
                param_name = input("Enter parameter name for SQL Injection: ")
                test_sql_injection(url, param_name)
            elif selection == 3:
                url = input("Enter URL for Brute Force Login test: ")
                username_param = input("Enter username parameter: ")
                password_param = input("Enter password parameter: ")
                test_brute_force_login(url, username_param, password_param)
            elif selection == 4:
                url = input("Enter URL for Reflected XSS test: ")
                param_name = input("Enter parameter name for XSS test: ")
                test_reflected_xss(url, param_name)
            elif selection == 5:
                url = input("Enter URL for Access Control test: ")
                param_name = input("Enter parameter name for Access Control test: ")
                test_access_control(url, param_name)
            elif selection == 6:
                print("Exiting the script.")
                print("Tests completed. Review your report for findings.")
                break
            else:
                print("Invalid selection, please try again.")
        except ValueError:
            print("Please enter a valid number.")

if __name__ == "__main__":
    main()
