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
from urllib.parse import urljoin
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
    splash = """
    [Your Splash Here]
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

# Attack Modules

# Time of Check to Time of Use (TOCTOU) Race Condition Testing
def test_toctou_race_condition(url, param_name):
    payload = "/tmp/testfile"
    data = {param_name: payload}
    
    # Step 1: Check if the file exists before upload
    initial_check = SESSION.get(url, headers=HEADERS)
    initial_check_status = "File exists" if "testfile" in initial_check.text else "File does not exist"
    
    # Simulate race condition by waiting for a brief period
    time.sleep(3)  # Adjust sleep to simulate a TOCTOU window
    response = SESSION.post(url, data=data, headers=HEADERS)
    
    # Step 2: Check file status after "upload"
    final_check = SESSION.get(url, headers=HEADERS)
    final_check_status = "File exists" if "testfile" in final_check.text else "File does not exist"
    
    if initial_check_status != final_check_status:
        log_report("TOCTOU Race Condition", "Vulnerable", f"TOCTOU detected with file upload payload.")
        return "TOCTOU Race Condition: Vulnerable"
    
    log_report("TOCTOU Race Condition", "Not Vulnerable", "No TOCTOU vulnerability detected.")
    return "TOCTOU Race Condition: Not Vulnerable"

# File Upload and Webshell Testing
def test_file_upload_webshell(url, param_name, file_path):
    # Check if the file extension is allowed
    allowed_extensions = ['.php', '.jsp', '.asp', '.sh']
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1].lower()

    if file_extension not in allowed_extensions:
        log_report("File Upload", "Not Vulnerable", "File extension not allowed.")
        return "File Upload: Not Vulnerable"

    # Try uploading a web shell
    files = {'file': (file_name, open(file_path, 'rb'), mimetypes.guess_type(file_path)[0])}
    data = {param_name: "webshell"}
    response = SESSION.post(url, files=files, data=data, headers=HEADERS)
    
    # Check if the file is uploaded and accessible
    uploaded_file_url = urljoin(url, f"/uploads/{file_name}")
    uploaded_response = SESSION.get(uploaded_file_url, headers=HEADERS)
    
    if uploaded_response.status_code == 200 and "webshell" in uploaded_response.text:
        log_report("File Upload", "Vulnerable", f"Web shell uploaded successfully: {file_name}")
        return f"File Upload: Vulnerable (Web shell uploaded)"
    
    log_report("File Upload", "Not Vulnerable", "File upload failed or not vulnerable.")
    return "File Upload: Not Vulnerable"

# SQL Injection Test (Non-destructive)
def test_sql_injection(url, param_name):
    payloads = [
        "' OR 1=1 --",  # Classic SQL Injection
        "' AND 1=1#",  # Another variation of injection
    ]
    
    for payload in payloads:
        data = {param_name: payload}
        response = SESSION.post(url, data=data, headers=HEADERS)
        if "error" in response.text or "syntax" in response.text:
            log_report("SQL Injection", "Vulnerable", f"SQL Injection detected with payload: {payload}")
            return f"SQL Injection: Vulnerable (Payload: {payload})"
    
    log_report("SQL Injection", "Not Vulnerable", "No SQL Injection detected.")
    return "SQL Injection: Not Vulnerable"

# Main Script
def main():
    display_splash_screen()
    initialize_report()
    print(Fore.CYAN + "Select a test to run: ")
    
    options = [
        "Discover Links",
        "Test SQL Injection",
        "Test Blind SQL Injection",
        "Test Stored XSS",
        "Test Reflected XSS",
        "Test Command Injection",
        "Test Path Traversal",
        "Test RFI",
        "TOCTOU Race Condition",
        "Test File Upload (Web Shell)",
        "Exit"
    ]
    
    display_in_columns(options)
    
    while True:
        selection = input(f"Select an option (1-{len(options)}): ")
        
        try:
            selection = int(selection)
            if selection == 1:
                # Placeholder for link discovery
                print("Link discovery not implemented yet.")
            elif selection == 2:
                url = input("Enter URL for SQL Injection test: ")
                param_name = input("Enter parameter name for SQL Injection: ")
                print(test_sql_injection(url, param_name))
            elif selection == 10:
                file_path = input("Enter file path for Web Shell test: ")
                url = input("Enter URL for File Upload test: ")
                param_name = input("Enter parameter name for file upload: ")
                print(test_file_upload_webshell(url, param_name, file_path))
            elif selection == 11:
                print("Exiting the script.")
                print("Tests completed. Review your report for findings.")
                break
            else:
                print("Invalid selection, please try again.")
        except ValueError:
            print("Please enter a valid number.")

if __name__ == "__main__":
    main()
