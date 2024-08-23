from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import oqs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

kemalg = "Kyber512"

class EncryptDecryptRequest(BaseModel):
    message: str
    mode: str  # "encode" or "decode"

class SaveRequest(BaseModel):
    encrypted_data: str

@app.post("/process/")
async def process_message(request: EncryptDecryptRequest):
    with oqs.KeyEncapsulation(kemalg) as client:
        public_key = client.generate_keypair()

        with oqs.KeyEncapsulation(kemalg) as server:
            ciphertext, shared_secret_server = server.encap_secret(public_key)
        
        shared_secret_client = client.decap_secret(ciphertext)

    if shared_secret_client != shared_secret_server:
        raise HTTPException(status_code=500, detail="Shared secrets do not match!")

    if request.mode == "encode":
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(shared_secret_client), modes.GCM(iv), backend=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(request.message.encode()) + encryptor.finalize()
        tag = encryptor.tag
        encrypted_message = base64.b64encode(iv + ciphertext + tag).decode()
        return {"result": encrypted_message}
    
    elif request.mode == "decode":
        try:
            decoded_data = base64.b64decode(request.message)
            iv, ciphertext, tag = decoded_data[:12], decoded_data[12:-16], decoded_data[-16:]
            decryptor = Cipher(algorithms.AES(shared_secret_server), modes.GCM(iv, tag), backend=None).decryptor()
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
            return {"result": decrypted_message.decode()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    else:
        raise HTTPException(status_code=400, detail="Invalid mode. Choose 'encode' or 'decode'.")

@app.post("/save/")
async def save_to_db(request: SaveRequest):
    encrypted_data = request.encrypted_data
    conn = psycopg2.connect(
        dbname="sholk",
        user="postgres",
        password="Shubham@03",
        host="localhost"
    )
    cursor = conn.cursor()
    cursor.execute("INSERT INTO quantum_cryptography (encrypted_data) VALUES (%s)", (encrypted_data,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success"}

@app.get("/data/")
async def get_data():
    conn = psycopg2.connect(
        dbname="sholk",
        user="postgres",
        password="Shubham@)3",
        host="localhost"
    )
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quantum_cryptography")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return {"data": rows}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5056)
