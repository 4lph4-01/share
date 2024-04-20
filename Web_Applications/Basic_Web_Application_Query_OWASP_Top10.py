#########################################################################################################################################################################################
# Basic Python script to look at a web application for possible vulnerabilities.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# Lets work together to get the full top ten coded?
#########################################################################################################################################################################################


import re

def find_sql_injections(code):
    sql_injections = []
    # Regular expression pattern to match potential SQL injection patterns
    pattern = r"SELECT\s+\*?\s+FROM\s+(\w+)\s+WHERE\s+(.+?)(=|>|<|!=|IN|LIKE)\s+(?:'|\")(.+?)(?:'|\")"

    # Find matches in the code
    matches = re.finditer(pattern, code, re.IGNORECASE)
    for match in matches:
        table_name = match.group(1)
        column_name = match.group(2)
        operator = match.group(3)
        value = match.group(4)
        sql_injections.append({
            "type": "SQL Injection",
            "table_name": table_name,
            "column_name": column_name,
            "operator": operator,
            "value": value
        })

    return sql_injections

def find_xss_vulnerabilities(code):
    xss_vulnerabilities = []
    # Regular expression pattern to match potential XSS vulnerabilities
    pattern = r"(?:<|&lt;)(?:script|img|iframe).+?(?:>|&gt;)(?:.*?)(?:<\/|&lt;)script(?:>|&gt;)"

    # Find matches in the code
    matches = re.finditer(pattern, code, re.IGNORECASE)
    for match in matches:
        xss_vulnerabilities.append({
            "type": "Cross-Site Scripting (XSS)",
            "payload": match.group(0)
        })

    return xss_vulnerabilities

def find_ssrf_vulnerabilities(code):
    ssrf_vulnerabilities = []
    # Regular expression pattern to match potential SSRF vulnerabilities
    pattern = r"(http|https|ftp)://(\w+\.)*\w+"

    # Find matches in the code
    matches = re.finditer(pattern, code, re.IGNORECASE)
    for match in matches:
        ssrf_vulnerabilities.append({
            "type": "Server-Side Request Forgery (SSRF)",
            "url": match.group(0)
        })

    return ssrf_vulnerabilities

def find_owasp_top_10_vulnerabilities(code):
    vulnerabilities = []
    vulnerabilities.extend(find_sql_injections(code))
    vulnerabilities.extend(find_xss_vulnerabilities(code))
    vulnerabilities.extend(find_ssrf_vulnerabilities(code))
    # Add additional checks for other OWASP Top 10 vulnerabilities here

    return vulnerabilities

def main():
    # Example code containing potential vulnerabilities
    code = """
    SELECT * FROM users WHERE username = 'admin' AND password = 'password123';
    SELECT * FROM products WHERE id = 1 OR 1=1;
    <script>alert('XSS vulnerability');</script>
    FetchResource('http://internal-server/admin-panel');
    """

    owasp_top_10_vulnerabilities = find_owasp_top_10_vulnerabilities(code)

    if owasp_top_10_vulnerabilities:
        print("Potential OWASP Top 10 vulnerabilities found:")
        for vulnerability in owasp_top_10_vulnerabilities:
            print(vulnerability)
    else:
        print("No potential OWASP Top 10 vulnerabilities found in the code.")

if __name__ == "__main__":
    main()
