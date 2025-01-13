#####################################################################################################################################################################
# Initial python to search the internet and darkweb for exposed email addresses, associated with the supplied domain. Requires a virtual environment in Linux, for dependancies.  
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
import os
import requests
import re
import csv
import time
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from queue import Queue
from threading import Thread

# Ethical disclaimer
def ethical_disclaimer():
    print("This tool is designed for ethical purposes only.")
    print("By using this tool, you agree to use it responsibly and within legal boundaries.")
    print("You should only scan websites you own or have permission to scan.")
    response = input("Do you agree to use this tool ethically and with permission? (yes/no): ")
    if response.strip().lower() != "yes":
        print("Exiting... Please use the tool ethically in the future.")
        sys.exit(0)

ethical_disclaimer()

# Check for virtual environment
def check_virtual_env():
    if not hasattr(sys, 'real_prefix') and not os.getenv('VIRTUAL_ENV'):
        print("It seems you are not running this script in a virtual environment.")
        print("To avoid system conflicts, it's recommended to set up a virtual environment.")
        sys.exit(1)

check_virtual_env()

# Banner
def display_splash_screen():
    splash = r"""
    
___________               .__.__          ___ ___                                        __  .__                             _____  ____.____   __________  ___ ___    _____           _______  ____ 
\_   _____/ _____ _____   |__|  |        /   |   \_____  __________  __  ____    _______/  |_|__| ____   ____               /  |  |/_   |    |  \______   \/   |   \  /  |  |          \   _  \/_   |
 |    __)_ /     \\__  \  |  |  |       /    ~    \__  \ \_  __ \  \/ /_/ __ \  /  ___/\   __\  |/    \ / ___\    ______   /   |  |_|   |    |   |     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 |        \  Y Y  \/ __ \_|  |  |__     \    Y    // __ \_|  | \/\   / \  ___/  \___ \  |  | |  |   |  | /_/  >  /_____/  /    ^   /|   |    |___|    |   \    Y    /    ^   / /_____/ \  \_/   \   |
/_______  /__|_|  (____  /|__|____/______\___|_  /(____  /|__|    \_/   \___  >/____  > |__| |__|___|  |___  /            \____   | |___|_______ \____|    \___|_  /\____   |           \_____  /___|
        \/      \/     \/         /_____/      \/      \/                   \/      \/               \/_____/                  |__|             \/               \/      |__|                 \/  

  (_ _)                                           
   | |____....----....____         _                           
   | |\                . .~~~~---~~ |                           
   | | |         __\\ /(/(  .       |                           
   | | |      <--= '|/_/_( /|       |                           
   | | |       }\~) | / _(./      ..|                           
   | | |.:::::::\\/      --...::::::|                           
   | | |:::::::::\//::\\__\:::::::::|                           
   | | |::::::::_//_:_//__\\_:::::::|                           
   | | |::::::::::::::::::::::::::::|                           
   | |/:::''''~~~~'''':::::::::::::'~                           
   | |                                                    
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
    print("Email Address Harvesting Tool\n")

display_splash_screen()

# Dependencies check and installation
required_packages = ["requests[socks]", "beautifulsoup4"]

def install(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"{package} installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {package}: {e}. Please install it manually.")
        sys.exit(1)

for package in required_packages:
    try:
        __import__(package.split('[')[0])
    except ImportError:
        print(f"Installing {package}...")
        install(package)

# API keys prompt
def get_api_keys():
    print("Please enter your API keys.")
    spiderfoot_api_key = input("Spiderfoot API Key (or press Enter to skip): ")
    hunter_api_key = input("Hunter API Key (or press Enter to skip): ")
    clearbit_api_key = input("Clearbit API Key (or press Enter to skip): ")
    return spiderfoot_api_key, hunter_api_key, clearbit_api_key

SPIDERFOOT_API_KEY, HUNTER_API_KEY, CLEARBIT_API_KEY = get_api_keys()

# Create session with retries
def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

# API Integration Functions (Spiderfoot, Hunter, Clearbit)
def spiderfoot_darkweb_search(domain):
    # Placeholder function for Spiderfoot
    return []

def hunter_search(domain):
    # Placeholder function for Hunter.io
    return []

def clearbit_search(domain):
    # Placeholder function for Clearbit
    return []

# Web scraping to find emails
def scrape_emails_from_page(url, session):
    emails = set()
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails.update(re.findall(email_pattern, soup.get_text()))
        print(f"Emails found on {url}: {emails}")
    except requests.RequestException as e:
        logging.error(f"Error scraping {url}: {e}")
    return emails

# Crawl a domain and scrape emails from multiple pages
def crawl_domain(domain, num_pages, session):
    visited = set()
    to_visit = Queue()
    to_visit.put(f"http://{domain}")

    emails = set()

    while not to_visit.empty() and len(visited) < num_pages:
        url = to_visit.get()
        if url not in visited:
            visited.add(url)
            print(f"Visiting {url}")
            emails.update(scrape_emails_from_page(url, session))

            # Find internal links on the page to visit next
            try:
                response = session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [urljoin(url, link['href']) for link in soup.find_all('a', href=True)]
                for link in links:
                    if urlparse(link).netloc == domain:
                        to_visit.put(link)
            except requests.RequestException as e:
                logging.error(f"Error fetching links from {url}: {e}")
                
            # Add a delay to avoid overloading the server
            time.sleep(2)
            
    return emails

# Main email finding function
def find_emails(domain, num_pages=1):
    session = create_session()

    # Web scraping for email addresses from the domain
    emails = crawl_domain(domain, num_pages, session)

    # Add API-based searches if API keys are provided
    if SPIDERFOOT_API_KEY:
        emails.update(spiderfoot_darkweb_search(domain))
    if HUNTER_API_KEY:
        emails.update(hunter_search(domain))
    if CLEARBIT_API_KEY:
        emails.update(clearbit_search(domain))

    return list(emails)

# Save results to CSV
def save_to_csv(emails, filename="email_results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Email Address"])
        for email in emails:
            writer.writerow([email])

# Main execution
if __name__ == "__main__":
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    num_pages = int(input("How many pages would you like to crawl? (e.g., 5): ").strip())
    
    emails = find_emails(domain, num_pages)
    
    if emails:
        print(f"Email addresses found for {domain}:")
        for email in emails:
            print(email)
        save_to_csv(emails)
        print(f"Results saved to email_results.csv")
    else:
        print(f"No email addresses found for {domain}.")

