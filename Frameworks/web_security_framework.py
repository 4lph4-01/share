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

import os
import time
import requests
import threading
import mimetypes
from urllib.parse import urljoin, quote
from datetime import datetime
from colorama import Fore, Style
from bs4 import BeautifulSoup
import re
import csv

# Global Settings
TARGET_URL = "http://example.com"  # Replace with actual target
SESSION = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

REPORT_FILE = 'vulnerability_report.csv'

# Allowed domains and paths
ALLOWED_DOMAINS = ["example.com", "sub.example.com"]  # Add domains or subdomains to crawl
ALLOWED_PATHS = ["/admin/", "/uploads/"]  # Add allowed paths to crawl

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
    splash = r"""
 __      __        ___.            _________                           .__   __                ___________                                                  __                  _____  ____         .__       _____           _______  ____ 
/  \    /  \  ____ \_ |__         /   _____/ ____   ____   __ _________|__|_/  |_  ___.__.     \_   _____/____________     _____   ______  _  _____________|  | __             /  |  |/_   |______  |  |__   /  |  |          \   _  \/_   |
\   \/\/   /_/ __ \ | __ \        \_____  \_/ __ \_/ ___\ |  |  \_  __ \  |\   __\<   |  |      |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  |_|   |\____ \ |  |  \ /   |  |_  ______ /  /_\  \|   |
 \        / \  ___/ | \_\ \       /        \  ___/\  \___ |  |  /|  | \/  | |  |   \___  |      |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /|   ||  |_> >|   Y  |    ^   / /_____/ \  \_/   \   |
  \__/\  /   \___  >|___  /______/_______  /\___  >\___  >|____/ |__|  |__| |__|   / ____|______\___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   | |___||   __/ |___|  |____   |           \_____  /___|
       \/        \/     \//_____/        \/     \/     \/                          \/    /_____/    \/                \/       \/     \/                        \/                |__|      |__|         \/     |__|                 \/     
       
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
    print("Web_Application_Security_Framework 41PH4-01\n")

# Columnar Display Helper Function
def display_in_columns(options):
    max_length = max(len(option) for option in options)
    formatted_options = [
        f"[{index+1}] {option:<{max_length}}" 
        for index, option in enumerate(options)
    ]
    print("    ".join(formatted_options))

# Payload Obfuscation Functions
def url_encode(payload):
    return quote(payload)

def obfuscate_sql_injection(payload):
    payload = payload.replace("OR", "O%52")  # Obfuscating the OR
    payload = payload.replace("AND", "A%4E%44")  # Obfuscating AND
    payload = url_encode(payload)  # URL encode the payload
    return payload

def obfuscate_xss(payload):
    payload = payload.replace("<script>", "<ScRiPt>")  # Mixed case obfuscation
    payload = payload.replace("</script>", "<&#115;cript>")  # Encode part of the closing tag
    return payload

def obfuscate_command_injection(payload):
    payload = payload.replace(";", "%3B")  # Obfuscate semicolon
    payload = payload.replace("|", "%7C")  # Obfuscate pipe symbol
    return url_encode(payload)

# Attack Modules
def test_sql_injection(url, param_name):
    payloads = ["' OR 1=1 --", "' AND 1=1#"]
    for payload in payloads:
        obfuscated_payload = obfuscate_sql_injection(payload)
        data = {param_name: obfuscated_payload}
        response = SESSION.post(url, data=data, headers=HEADERS)
        if "error" in response.text or "syntax" in response.text:
            log_report("SQL Injection", "Vulnerable", f"Payload: {obfuscated_payload}")
            return f"SQL Injection: Vulnerable (Payload: {obfuscated_payload})"
    log_report("SQL Injection", "Not Vulnerable", "No SQL Injection detected.")
    return "SQL Injection: Not Vulnerable"

def test_xss(url, param_name):
    payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    for payload in payloads:
        obfuscated_payload = obfuscate_xss(payload)
        data = {param_name: obfuscated_payload}
        response = SESSION.post(url, data=data, headers=HEADERS)
        if "alert('XSS')" in response.text or "alert(1)" in response.text:
            log_report("XSS", "Vulnerable", f"Payload: {obfuscated_payload}")
            return f"XSS: Vulnerable (Payload: {obfuscated_payload})"
    log_report("XSS", "Not Vulnerable", "No XSS detected.")
    return "XSS: Not Vulnerable"

def test_file_upload_webshell(url, param_name, file_path):
    allowed_extensions = ['.php', '.jsp', '.asp', '.sh']
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1].lower()
    if file_extension not in allowed_extensions:
        log_report("File Upload", "Not Vulnerable", "File extension not allowed.")
        return "File Upload: Not Vulnerable"

    files = {'file': (file_name, open(file_path, 'rb'), mimetypes.guess_type(file_path)[0])}
    data = {param_name: "webshell"}
    response = SESSION.post(url, files=files, data=data, headers=HEADERS)
    uploaded_file_url = urljoin(url, f"/uploads/{file_name}")
    uploaded_response = SESSION.get(uploaded_file_url, headers=HEADERS)
    if uploaded_response.status_code == 200:
        log_report("File Upload", "Vulnerable", f"Web shell uploaded: {file_name}")
        return f"File Upload: Vulnerable"
    log_report("File Upload", "Not Vulnerable", "No vulnerability detected.")
    return "File Upload: Not Vulnerable"

def extract_forms_and_hidden_fields(url):
    response = SESSION.get(url, headers=HEADERS)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    form_data = []
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'GET').upper()
        hidden_fields = {input_tag.get('name'): input_tag.get('value') for input_tag in form.find_all('input', type='hidden')}
        form_data.append({'action': action, 'method': method, 'hidden_fields': hidden_fields})
    return form_data

# Main Script
def main():
    display_splash_screen()
    initialize_report()
    print(Fore.CYAN + "Select a test to run: ")
    options = [
        "Test SQL Injection", "Test XSS",
        "Test File Upload (Web Shell)", "Extract Forms and Hidden Fields", "Exit"
    ]
    display_in_columns(options)
    while True:
        selection = input(f"Select an option (1-{len(options)}): ")
        try:
            selection = int(selection)
            if selection == 1:
                url = input("Enter URL for SQL Injection test: ")
                param_name = input("Enter parameter name: ")
                print(test_sql_injection(url, param_name))
            elif selection == 2:
                url = input("Enter URL for XSS test: ")
                param_name = input("Enter parameter name: ")
                print(test_xss(url, param_name))
            elif selection == 3:
                file_path = input("Enter file path for File Upload test: ")
                url = input("Enter URL: ")
                param_name = input("Enter parameter name: ")
                print(test_file_upload_webshell(url, param_name, file_path))
            elif selection == 4:
                url = input("Enter URL to extract forms: ")
                forms = extract_forms_and_hidden_fields(url)
                print(forms)
            elif selection == 5:
                print("Exiting...")
                break
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a valid number.")

if __name__ == "__main__":
    main()
