import os
import hashlib
import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

#========================= Setup =========================
# Load private key
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

# Load public key
def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Get environment variables or defaults
KRA_ID = os.getenv("KRA_ID", "kra1")  # e.g., kra1, kra2, ...
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", f"./keys/{KRA_ID}_private.pem")
PUBLIC_KEY_PATH = os.getenv("PUBLIC_KEY_PATH", f"./keys/krc_public.pem")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 5003))  # Each KRA has a unique port

# Load keys
kra_private_key = load_private_key(PRIVATE_KEY_PATH)
krc_public_key = load_public_key(PUBLIC_KEY_PATH)

def decrypt_message(encrypted_message):
    return kra_private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_message(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def handle_client(client_socket):
    try:
        # Receive data
        data = client_socket.recv(4096)
        if not data:
            return
        
        # Parse data (assumes a simple JSON protocol)
        message = json.loads(data.decode('utf-8'))
        
        if message["type"] == "challenge":
            encrypted_challenge = bytes.fromhex(message["encrypted_data"])
            challenge_code = decrypt_message(encrypted_challenge)
            
            # Generate challenge verifier
            challenge_verifier = hashlib.sha256(challenge_code).digest()
            
            # Encrypt verifier with KRC's public key
            encrypted_verifier = encrypt_message(challenge_verifier, krc_public_key)
            response = {
                "type": "challenge_response",
                "challenge_verifier": encrypted_verifier.hex()
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
        
        elif message["type"] == "krf_retrieval":
            encrypted_krf_i = bytes.fromhex(message["encrypted_krf_i"])
            krf_i = decrypt_message(encrypted_krf_i)
            
            # Re-encrypt KRF-i with KRC's public key
            re_encrypted_krf_i = encrypt_message(krf_i, krc_public_key)
            response = {
                "type": "krf_response",
                "encrypted_krf_i": re_encrypted_krf_i.hex()
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
        
    except Exception as e:
        error_response = {"status": "error", "message": str(e)}
        client_socket.send(json.dumps(error_response).encode('utf-8'))
    finally:
        client_socket.close()

#========================= Main =========================
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", LISTEN_PORT))
    server_socket.listen(5)
    print(f"{KRA_ID} listening on port {LISTEN_PORT}")
    
    while True:
        client_socket, _ = server_socket.accept()
        handle_client(client_socket)

if __name__ == "__main__":
    main()
