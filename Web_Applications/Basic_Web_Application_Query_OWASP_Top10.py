#########################################################################################################################################################################################
# Basic Python script to look at a web application for possible vulnerabilities in a web application.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# Lets work together to get the full top ten coded?
#########################################################################################################################################################################################


import requests

vulnerabilities = {
    "A01:2021-Broken Access Control": "/example_endpoint",  # Change "/example_endpoint" to your endpoint
    "A02:2021-Cryptographic Failures": "/example_endpoint",
    "A03:2021-Injection": "/example_endpoint",
    "A04:2021-Insecure Design": "/example_endpoint",
    "A05:2021-Security Misconfiguration": "/example_endpoint",
    "A06:2021-Vulnerable and Outdated Components": "/example_endpoint",
    "A07:2021-Identification and Authentication Failures": "/example_endpoint",
    "A08:2021-Software and Data Integrity Failures": "/example_endpoint",
    "A09:2021-Security": "/example_endpoint",
    "A10:2021-Server-Side Request Forgery": "/example_endpoint"
}

base_url = "http://your_base_url"  # Change "http://your_base_url" to your base URL

def test_vulnerabilities():
    for vulnerability, endpoint in vulnerabilities.items():
        url = base_url + endpoint
        response = requests.get(url)
        if response.status_code == 200:
            print(f"Vulnerability {vulnerability} may be present at {url}")
        else:
            print(f"Vulnerability {vulnerability} does not appear to be present at {url}")

if __name__ == "__main__":
    test_vulnerabilities()
