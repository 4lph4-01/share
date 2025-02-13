from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

app = FastAPI()
logging.basicConfig(filename="c2_server.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

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

class KeyExchangeRequest(BaseModel):
    AgentID: str
    EncAESKey: str

@app.post("/exchange_key")
def exchange_key(request: KeyExchangeRequest):
    """Handle the key exchange request from agents."""
    logging.info(f"Key exchange requested by AgentID: {request.AgentID}")
    # Here you would normally handle the key exchange logic
    # For this example, we will just return a success message
    return {"Status": "Success"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
