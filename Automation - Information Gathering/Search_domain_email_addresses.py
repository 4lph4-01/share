import subprocess
import sys
import requests
import re
import csv
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Automatically install missing dependencies
required_packages = ["requests[socks]", "beautifulsoup4"]
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

for package in required_packages:
    try:
        __import__(package.split('[')[0])  # Import base module (e.g., 'requests' from 'requests[socks]')
    except ImportError:
        print(f"Installing {package}...")
        install(package)

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

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

# SpiderFoot search
def spiderfoot_search(domain):
    payload = {
        'scanTarget': domain,
        'scanType': 'domain',
        'apiKey': SPIDERFOOT_API_KEY
    }
    try:
        response = requests.post(f"{SPIDERFOOT_API_URL}/scan/new", json=payload)
        response.raise_for_status()
        scan_id = response.json().get('scan_id')

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

# Dark Web Search with Tor
def dark_web_search(domain):
    onion_urls = [
        "http://exampledarkweb.onion",  # Add actual onion links here
    ]
    session = create_session()
    emails = set()
    email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
    
    for url in onion_urls:
        try:
            response = session.get(url, proxies=TOR_PROXY, timeout=10)
            response.raise_for_status()
            emails.update(re.findall(email_pattern, response.text))
        except requests.RequestException as e:
            print(f"Error accessing {url} on dark web: {e}")

    return list(emails)

# Main function to combine all searches
def find_emails(domain):
    emails = set()
    emails.update(spiderfoot_search(domain))
    emails.update(hunter_search(domain))
    emails.update(clearbit_search(domain))
    emails.update(pipl_search(domain))
    emails.update(dark_web_search(domain))
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

