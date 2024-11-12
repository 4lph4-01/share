#####################################################################################################################################################################
# Initial python to search the internet and darkweb for exposed email addresses, associated with the supplied domain. Note: API's required, TOR installation and port, for additional dark web integration.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the       
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, # and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#####################################################################################################################################################################


import subprocess
import sys
import requests
import re
import csv
import time
from random import choice
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def display_splash_screen():
    splash = """
    
  

___________              .__.__          _____       .___  .___                                  ___ ___                                     __  .__                              _____ ____       .__        _____           _______  ____ 
\_   _____/ _____ _____  |__|  |        /  _  \    __| _/__| _/______   ____   ______ ______    /   |   \_____ __________  __ ____   _______/  |_|__| ____    ____               /  |  /_   |_____ |  |__    /  |  |          \   _  \/_   |
 |    __)_ /     \\__  \ |  |  |       /  /_\  \  / __ |/ __ |\_  __ \_/ __ \ /  ___//  ___/   /    ~    \__  \\_  __ \  \/ // __ \ /  ___/\   __\  |/    \  / ___\    ______   /   |  ||   \____ \|  |  \  /   |  |_  ______ /  /_\  \|   |
 |        \  Y Y  \/ __ \|  |  |__    /    |    \/ /_/ / /_/ | |  | \/\  ___/ \___ \ \___ \    \    Y    // __ \|  | \/\   /\  ___/ \___ \  |  | |  |   |  \/ /_/  >  /_____/  /    ^   /   |  |_> >   Y  \/    ^   / /_____/ \  \_/   \   |
/_______  /__|_|  (____  /__|____/____\____|__  /\____ \____ | |__|    \___  >____  >____  >____\___|_  /(____  /__|    \_/  \___  >____  > |__| |__|___|  /\___  /            \____   ||___|   __/|___|  /\____   |           \_____  /___|
        \/      \/     \/       /_____/       \/      \/    \/             \/     \/     \/_____/     \/      \/                 \/     \/               \//_____/                  |__|    |__|        \/      |__|                 \/     


 
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
    print("Email Address Harvesting 41PH4-01\n")

# Confirm ethical usage
def confirm_ethics():
    print("This tool is designed for ethical purposes only.")
    print("By using this tool, you agree to use it responsibly and within legal boundaries.")
    response = input("Do you agree to use this tool ethically and with permission? (yes/no): ")
    if response.strip().lower() != "yes":
        print("Exiting... Please use the tool ethically in the future.")
        sys.exit(0)
confirm_ethics()

# Automatically install missing dependencies with error handling
required_packages = ["requests[socks]", "beautifulsoup4"]
def install(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"{package} installed successfully.")
    except subprocess.CalledProcessError:
        print(f"Failed to install {package}. Please install it manually.")
        sys.exit(1)

for package in required_packages:
    try:
        __import__(package.split('[')[0])
    except ImportError:
        print(f"Installing {package}...")
        install(package)

# Check and install OSINT tools: SpiderFoot, OnionScan, and Recon-NG
def install_tool(tool_name, install_command):
    try:
        subprocess.check_call(install_command, shell=True)
        print(f"{tool_name} installed successfully.")
    except subprocess.CalledProcessError:
        print(f"Failed to install {tool_name}. Please install it manually and ensure it is accessible.")
        sys.exit(1)

# SpiderFoot installation check
try:
    subprocess.check_call(['spiderfoot', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    print("SpiderFoot not found. Installing SpiderFoot...")
    install_tool("SpiderFoot", "pip install spiderfoot")

# API and Tor configuration
SPIDERFOOT_API_URL = 'http://localhost:5001'  # SpiderFoot API URL
SPIDERFOOT_API_KEY = 'your_spiderfoot_api_key'  # SpiderFoot API Key
HUNTER_API_KEY = 'your_hunter_api_key'         # Hunter.io API Key
CLEARBIT_API_KEY = 'your_clearbit_api_key'     # Clearbit API Key
PIPL_API_KEY = 'your_pipl_api_key'             # Pipl API Key

# Tor SOCKS proxy settings
TOR_PROXY = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# Random User-Agent strings for simulating browser requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
]

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

# SpiderFoot search with Dark Web module
def spiderfoot_darkweb_search(domain):
    payload = {
        'scanTarget': domain,
        'scanType': 'domain',
        'modules': 'darkweb',  # Enable darkweb module
        'apiKey': SPIDERFOOT_API_KEY
    }
    try:
        response = requests.post(f"{SPIDERFOOT_API_URL}/scan/new", json=payload)
        response.raise_for_status()
        scan_id = response.json().get('scan_id')

        # Poll the SpiderFoot API for results
        result_response = requests.get(f"{SPIDERFOOT_API_URL}/scan/{scan_id}/results")
        result_response.raise_for_status()
        data = result_response.json()

        email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
        emails = set(re.findall(email_pattern, str(data)))
        return list(emails)
    except requests.RequestException as e:
        print(f"Error with SpiderFoot: {e}")
        return []

# Hunter.io search
def hunter_search(domain):
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        emails = [item['value'] for item in response.json().get('data', {}).get('emails', [])]
        return emails
    except requests.RequestException as e:
        print(f"Error with Hunter.io API: {e}")
        return []

# Clearbit search
def clearbit_search(domain):
    url = f"https://person.clearbit.com/v1/people/email/{domain}"
    headers = {"Authorization": f"Bearer {CLEARBIT_API_KEY}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        emails = [response.json().get('email')]
        return emails if emails[0] else []
    except requests.RequestException as e:
        print(f"Error with Clearbit API: {e}")
        return []

# Pipl search (if available for emails)
def pipl_search(domain):
    url = f"https://api.pipl.com/search/?email_domain={domain}&key={PIPL_API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        emails = [item['email'] for item in response.json().get('emails', [])]
        return emails
    except requests.RequestException as e:
        print(f"Error with Pipl API: {e}")
        return []

# Dark Web Search with Tor (optional, currently disabled)
# Uncomment and add onion URLs if you have specific .onion sites you want to query.
# onion_urls = [
#     "http://exampledarkweb.onion",  # Replace with actual .onion URLs if needed
# ]
# def dark_web_search(domain):
#     session = create_session()
#     emails = set()
#     email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
#     
#     for url in onion_urls:
#         try:
#             headers = {'User-Agent': choice(USER_AGENTS)}
#             response = session.get(url, headers=headers, proxies=TOR_PROXY, timeout=15)
#             response.raise_for_status()
#             emails.update(re.findall(email_pattern, response.text))
#             time.sleep(3)
#         except requests.RequestException as e:
#             print(f"Error accessing {url} on dark web: {e}")
# 
#     return list(emails)

# Main function to combine all searches
def find_emails(domain):
    emails = set()
    emails.update(spiderfoot_darkweb_search(domain))
    emails.update(hunter_search(domain))
    emails.update(clearbit_search(domain))
    emails.update(pipl_search(domain))
    # Uncomment the following line if you have enabled dark_web_search
    # emails.update(dark_web_search(domain))
    return list(emails)

# Function to save results to CSV
def save_to_csv(emails, filename="email_results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Email Address"])  # CSV header
        for email in emails:
            writer.writerow([email])

# Run the function and save results
domain = "example.com"  # Replace with the target domain
emails = find_emails(domain)

print(f"Email addresses found for {domain}:")
for email in emails:
    print(email)

# Save the results to a CSV file
save_to_csv(emails, "email_results.csv")
print(f"Results saved to email_results.csv")
