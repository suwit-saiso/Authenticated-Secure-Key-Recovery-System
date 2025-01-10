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

# Get the directory of the current script (to use as base path)
script_dir = os.path.abspath(os.path.dirname(__file__))

# Dynamically determine KRA ID from the folder name or environment variable
KRA_ID = os.getenv("KRA_ID", os.path.basename(script_dir))  # e.g., kra1, kra2, ...

# Paths for private key (within the current KRA folder) and shared public key
private_key_path = os.path.join(script_dir, "keys", f"{KRA_ID}_private.pem")
shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
krc_public_key_path = os.path.join(shared_keys_dir, "krc_public.pem")

# Port for the KRA (defaults to 5003, or can be set per KRA using an env variable)
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 5003 + int(KRA_ID[-1]) - 1))  # Ports 5003, 5004, etc.

# Load keys with error handling
try:
    kra_private_key = load_private_key(private_key_path)
    krc_public_key = load_public_key(krc_public_key_path)
except FileNotFoundError as e:
    raise FileNotFoundError(f"Key file not found: {e}")


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
        data = client_socket.recv(4096).decode()  # Convert bytes to string
        print("Loaded data from KRC:", data)
        if not data:
            return
        
        # Parse data (assumes a simple JSON protocol) JSON string into a Python dictionary
        message = json.loads(data)

        if message["type"] == "challenge":
            print("Extract challenge code.")
            encrypted_challenge = bytes.fromhex(message["encrypted_challenge_code"])
            challenge_code = decrypt_message(encrypted_challenge)
            
            # Generate challenge verifier
            print("hashing challenge code.")
            challenge_verifier = hashlib.sha256(challenge_code).digest()
            
            # Encrypt verifier with KRC's public key
            print("Encrypting challenge.")
            encrypted_verifier = encrypt_message(challenge_verifier, krc_public_key)
            response = {
                "type": "challenge_response",
                "encrypted_challenge_verifier": encrypted_verifier.hex()
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            print("Challenge code verifier send.")
        
        elif message["type"] == "krf_retrieval":
            print("Extract KRF-i.")
            encrypted_krf_i = bytes.fromhex(message["encrypted_krf_i"])
            print("Decrypt KRF-i.")
            krf_i = decrypt_message(encrypted_krf_i)
            
            # Re-encrypt KRF-i with KRC's public key
            print("Re-encrypt KRF-i.")
            re_encrypted_krf_i = encrypt_message(krf_i, krc_public_key)
            response = {
                "type": "krf_response",
                "encrypted_krf_i": re_encrypted_krf_i.hex()
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            print("KRF-i send.")
        
    except Exception as e:
        error_response = {"status": "error", "message": str(e)}
        client_socket.send(json.dumps(error_response).encode('utf-8'))
    finally:
        client_socket.close()

#========================= Main =========================
def main():
    print(f"DEBUG: {KRA_ID} script has started executing.")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("192.168.1.14", LISTEN_PORT))
    server_socket.listen(5)
    print(f"{KRA_ID} listening on port {LISTEN_PORT}")
    
    while True:
        client_socket, _ = server_socket.accept()
        handle_client(client_socket)

if __name__ == "__main__":
    main()
