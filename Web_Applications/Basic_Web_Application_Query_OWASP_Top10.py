######################################################################################################################################################################################################################
# Basic Python script for possible vulnerabilities in a web application, and define the scope of allowed domains. The script is an intial test, and does not constitute or replace a robust vulnerability scanner "Yet"
# python vulnerability_tester.py. Note, script require BeautifulSoup Ref:https://beautiful-soup-4.readthedocs.io/en/latest/. 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# Replace /example_endpoint with the specific endpoints you want to test for each vulnerability. Replace "http://your_base_url" with the base URL of the application you're testing
######################################################################################################################################################################################################################

import requests
from bs4 import BeautifulSoup
import re

def display_splash_screen():
    splash = """
    
 __      __      ___.        _____                .__  .__               __  .__                             _____ ______________  ___ ___    _____           _______  ____ 
/  \    /  \ ____\_ |__     /  _  \ ______ ______ |  | |__| ____ _____ _/  |_|__| ____   ____               /  |  /_   \______   \/   |   \  /  |  |          \   _  \/_   |
\   \/\/   // __ \| __ \   /  /_\  \\____ \\____ \|  | |  |/ ___\\__  \\   __\  |/  _ \ /    \    ______   /   |  ||   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
 \        /\  ___/| \_\ \ /    |    \  |_> >  |_> >  |_|  \  \___ / __ \|  | |  (  <_> )   |  \  /_____/  /    ^   /   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
  \__/\  /  \___  >___  / \____|__  /   __/|   __/|____/__|\___  >____  /__| |__|\____/|___|  /           \____   ||___||____|    \___|_  /\____   |           \_____  /___|
       \/       \/    \/          \/|__|   |__|                \/     \/                    \/                 |__|                     \/      |__|                 \/  
 
 
 
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
    print("Wifi Attack Tool 41PH4-01\n")

# Function to crawl the website and discover URLs and forms within the scope
def crawl_website(base_url, scope):
    discovered_urls = set()
    discovered_forms = []

    # Recursive function to crawl URLs
    def crawl(url):
        response = requests.get(url)
        discovered_urls.add(url)

        # Parse HTML content
        soup = BeautifulSoup(response.content, 'html.parser')

        # Discover forms
        forms = soup.find_all('form')
        for form in forms:
            form_details = {
                'action': form.get('action'),
                'method': form.get('method'),
                'fields': []
            }
            # Discover all input fields within forms, including hidden fields
            inputs = form.find_all('input')
            for input_tag in inputs:
                field_type = input_tag.get('type')
                field_name = input_tag.get('name')
                form_details['fields'].append({'type': field_type, 'name': field_name})
            discovered_forms.append(form_details)

        # Recursively crawl links within the scope
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            if href.startswith(base_url) and href not in discovered_urls:
                if any(domain in href for domain in scope):
                    crawl(href)

    crawl(base_url)
    return discovered_forms

# Function to test form fields for vulnerabilities
def test_form_fields(forms):
    for form in forms:
        action = form['action']
        method = form['method']
        form_fields = form['fields']
        payloads = generate_payloads(form_fields)
        # Send requests with payloads and analyse responses
        # Example: send requests to action endpoint with payloads injected into form fields
        for payload in payloads:
            # Send request
            if method == 'GET':
                response = requests.get(action, params=payload)
            else:
                response = requests.post(action, data=payload)
            # Analyse response for indications of vulnerabilities
            analyze_response(response)

# Function to generate payloads for form fields
def generate_payloads(form_fields):
    # Example: generate SQL injection payloads for text input fields
    payloads = []
    for field in form_fields:
        if field['type'] == 'text':
            payloads.append({field['name']: "' OR 1=1--"})
        # Add more payload generation logic for other types of fields and vulnerabilities
    return payloads

# Function to analyse response for indications of vulnerabilities
def analyze_response(response):
    if re.search(r"error in your SQL syntax|mysql_fetch_array", response.text, re.IGNORECASE):
        print("SQL Injection vulnerability found in response:", response.url)
    if "<script>alert('XSS')</script>" in response.text:
        print("XSS vulnerability found in response:", response.url)
    # Add more checks for other vulnerabilities

# Main function to initiate crawling, form field testing, and reporting
def main(base_url, scope):
    discovered_forms = crawl_website(base_url, scope)
    test_form_fields(discovered_forms)
    # Log and report results

if __name__ == "__main__":
    base_url = "http://example.com"  # Change to the target website's base URL
    scope = ["example.com"]  # Define the scope of allowed domains
    main(base_url, scope)
