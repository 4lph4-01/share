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

## Setup

1. **Clone the Repository**
   git clone https://github.com/yourusername/Sovereign-C2.git
   cd Sovereign-C2

2. **Create and Activate Virtual Environment**
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3. **Install Dependencies**
   pip install -r requirements.txt

## Running the Server

Ensure all scripts are permissioned from root. /  chmod +x *.* in the root of sovereingn-c2

### Windows

1. **Run the script on the target Windows machine (with administrator privileges)**
   .\payloads\windows_payload.ps1

## Using the CLI

1. **List Agents**
   python cli/cli.py list-agents

2. **Deploy Payload**
   python cli/cli.py deploy-payload <agent_type>
   # Example: python cli/cli.py deploy-payload windows

3. **Select and Send Command to Agent**
   python cli/cli.py select-agent <AgentID>

4. **Generate Report**
   python cli/cli.py generate-report

## Example Commands

- `Get-ComputerInfo`
- `Get-Process`
- `Get-Service`
- `Test-Connection www.example.com`
- `Get-EventLog -LogName Application -Newest 10`

## Contributing
Contributions are welcome! Please submit a pull request or open an issue to discuss any changes or improvements.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
