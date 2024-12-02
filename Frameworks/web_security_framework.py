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
from urllib.parse import urljoin, urlencode
from datetime import datetime
from colorama import Fore, Style

# Global Settings
TARGET_URL = "http://example.com"  # Replace with actual target
SESSION = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

# Report File
REPORT_FILE = 'vulnerability_report.csv'

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
    }===={  }====={  }====={  }======{  }======{  }======={
   (______)(_______)(_______)(________)(________)(_________)
   
    """
    print(splash)
    print("Web_Application_Security_Framework 41PH4-01\n")

# Columnar Display Helper Function
def display_in_columns(options, column_count=2):
    max_length = max(len(option) for option in options)
    formatted_options = [
        f"[{index+1}] {option:<{max_length}}" 
        for index, option in enumerate(options)
    ]
    for i in range(0, len(formatted_options), column_count):
        print("    ".join(formatted_options[i:i + column_count]))

# Attack Modules

def test_race_condition(url, param_name, value):
    def send_request():
        data = {param_name: value}
        response = SESSION.post(url, data=data, headers=HEADERS)
        if response.status_code == 200:
            log_report("Race Condition", "Vulnerable", "Race condition vulnerability detected.")
        else:
            log_report("Race Condition", "Not Vulnerable", "No race condition detected.")

    threads = []
    for _ in range(10):  # 10 simultaneous requests
        thread = threading.Thread(target=send_request)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def test_business_logic(url, param_name):
    params = {param_name: "discount_code"}
    response = SESSION.get(url, params=params, headers=HEADERS)

    if "discount applied" in response.text:
        log_report("Business Logic", "Vulnerable", "Business logic vulnerability found")
    else:
        log_report("Business Logic", "Not Vulnerable", "No business logic vulnerability detected")

# Other tests would have similar changes:
# - Call `log_report()` at the end of each test function to record the results.

# Main Menu
def display_main_menu():
    print(f"\n{Fore.TEAL}Main Menu:{Style.RESET_ALL}")
    options = [
        "Race Condition (TOCTOU)", 
        "Business Logic Vulnerability", 
        "User Enumeration", 
        "HTTP Smuggling", 
        "Reflected File Download", 
        "Account Takeover", 
        "Blind SSRF", 
        "Memory Corruption", 
        "Subdomain Takeover", 
        "CORS Misconfiguration", 
        "Exit"
    ]
    display_in_columns(options, column_count=3)

# Main Script
def main():
    display_splash_screen()
    initialize_report()  # Initialize the report file

    while True:
        display_main_menu()
        try:
            choice = int(input(f"Choose an option (1-{len(options)}): "))

            if choice == 1:
                test_race_condition(TARGET_URL, "param_name", "value")
            elif choice == 2:
                test_business_logic(TARGET_URL, "param_name")
            # Add calls for other tests here with logging...
            elif choice == 11:
                print("Exiting...")
                break
            else:
                print(f"Invalid option. Please choose a number between 1 and {len(options)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    main()
