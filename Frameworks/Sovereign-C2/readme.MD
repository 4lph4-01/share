Share C2 Framework

Overview

Share is a Command and Control (C2) framework designed for post-exploitation activities, supporting multiple operating systems (Windows, Linux, macOS). It provides modules for credential harvesting, persistence, privilege escalation, reconnaissance, data exfiltration, keylogging, and lateral movement.

Features

Cross-platform payloads (Windows, Linux, macOS)

Modular structure for easy customization

Agent-based communication

Command-line interface (CLI) for management

Secure and encrypted C2 communication

Installation and Setup

1. Clone the Repository

git clone https://github.com/4lph4-01/share.git
cd share

2. Create a Virtual Environment

Linux/macOS:

python -m venv venv
source venv/bin/activate

Windows:

python -m venv venv
venv\Scripts\activate

3. Install Dependencies

pip install -r requirements.txt

4. Prepare Payloads (If necessary)

Ensure your payload scripts are in the payloads/ directory:

payloads/
  ├── macos_payload.sh
  ├── linux_payload.sh
  ├── windows_payload.ps1

Running the C2 Server

python c2_server.py

CLI Usage

List Agents

python cli.py list-agents

Deploy Payload

python cli.py deploy-payload <agent_type>

Replace <agent_type> with macos, linux, or windows.

Select and Send Commands to an Agent

python cli.py select-agent

You can specify the agent ID directly or choose from a list of available agents.

Generate Report

python cli.py generate-report

Send a Specific Command

python cli.py send-command <agent_id>

Supported Commands

Command

Description

cred_harvest

Credential Harvesting

persistence

Persistence Mechanism

priv_escalation

Privilege Escalation

reconnaissance

Reconnaissance

exfiltrate <file_path> <c2_url>

Data Exfiltration (Replace with actual file path & C2 URL)

keylogging

Keylogging

lateral_movement

Lateral Movement

Example Usage:

python cli.py send-command <agent_id> cred_harvest

Modules Directory Structure

Ensure you have a modules/ directory structured as follows:

modules/
  ├── cred_harvest.py
  ├── persistence.py
  ├── priv_escalation.py
  ├── reconnaissance.py
  ├── exfiltration.py
  ├── keylogging.py
  ├── lateral_movement.py

Disclaimer

This tool is intended for ethical penetration testing and security research purposes only. Ensure you have explicit permission before deploying and using this framework. Unauthorized use may violate laws and regulations.

Developed by 4lph4-01.


