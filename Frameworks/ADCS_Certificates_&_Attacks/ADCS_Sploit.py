import ldap3
import smtplib
import logging
import re
import json
from getpass import getpass
from ldap3 import Server, Connection, ALL
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
DRY_RUN = os.getenv("DRY_RUN", "False").lower() == "true"

# Input Validation Functions
def validate_server_address(address):
    pattern = r"^(https?://)?([a-zA-Z0-9.-]+)(:[0-9]+)?$"
    return re.match(pattern, address)

def validate_domain(domain):
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, domain)

def validate_template_name(template):
    return len(template) > 0

# LDAP Connection Setup
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

        # Save to JSON file
        with open("certificate_templates.json", "w") as file:
            json.dump(templates, file, indent=4)

        return templates
    except Exception as e:
        logger.error(f"Error enumerating certificate templates: {e}")
        return []

# Request Certificate
def request_certificate(template_name):
    if DRY_RUN:
        logger.info(f"Simulating certificate request for template: {template_name}")
        return True
    try:
        logger.info(f"Requesting certificate for template: {template_name}")
        # Placeholder for actual certificate request logic
        return True
    except Exception as e:
        logger.error(f"Failed to request certificate: {e}")
        return False

# NTLM Relay Attack
def ntlm_relay_attack(target_server, domain, username, password):
    if DRY_RUN:
        logger.info(f"Simulating NTLM relay attack on {target_server}")
        return True
    try:
        logger.info(f"Performing NTLM relay attack on {target_server}")
        # Placeholder for NTLM relay logic
        return True
    except Exception as e:
        logger.error(f"NTLM relay attack failed: {e}")
        return False

# Simulate Kerberos Golden Ticket Attack
def simulate_kerberos_golden_ticket():
    if DRY_RUN:
        logger.info("Simulating Kerberos Golden Ticket attack")
        return True
    try:
        logger.info("Simulating Kerberos Golden Ticket attack")
        # Placeholder for Golden Ticket simulation
        return True
    except Exception as e:
        logger.error(f"Golden Ticket simulation failed: {e}")
        return False

# Monitor ADCS Requests
def monitor_adcs_requests():
    try:
        logger.info("Monitoring ADCS certificate requests")
        # Placeholder for actual monitoring logic
    except Exception as e:
        logger.error(f"Error monitoring ADCS: {e}")

# Main Function
def main():
    global DRY_RUN

    # Get user inputs securely
    ldap_server = input("Enter LDAP server address: ").strip()
    if not validate_server_address(ldap_server):
        logger.error("Invalid LDAP server address. Exiting.")
        return

    adcs_server = input("Enter ADCS server address: ").strip()
    if not validate_server_address(adcs_server):
        logger.error("Invalid ADCS server address. Exiting.")
        return

    domain = input("Enter domain name: ").strip()
    if not validate_domain(domain):
        logger.error("Invalid domain name. Exiting.")
        return

    username = input("Enter username: ").strip()
    password = getpass("Enter password: ")

    # Set up LDAP connection
    server = Server(ldap_server, get_info=ALL)
    ldap_conn = setup_ldap_connection(server, username, password)
    if not ldap_conn:
        logger.error("LDAP connection failed. Exiting.")
        return

    # Enumerate certificate templates
    templates = enumerate_certificate_templates(ldap_conn)

    # Prompt user for next action
    logger.info("Select an action:")
    logger.info("1. Request Certificate")
    logger.info("2. Perform NTLM Relay Attack")
    logger.info("3. Simulate Golden Ticket")
    logger.info("4. Monitor ADCS Requests")
    choice = input("Enter your choice: ").strip()

    if choice == "1":
        template_name = input("Enter the template name: ").strip()
        if not validate_template_name(template_name):
            logger.error("Invalid template name. Exiting.")
            return
        request_certificate(template_name)
    elif choice == "2":
        target_server = input("Enter target server for NTLM relay: ").strip()
        if not validate_server_address(target_server):
            logger.error("Invalid target server address. Exiting.")
            return
        ntlm_relay_attack(target_server, domain, username, password)
    elif choice == "3":
        simulate_kerberos_golden_ticket()
    elif choice == "4":
        monitor_adcs_requests()
    else:
        logger.error("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()

