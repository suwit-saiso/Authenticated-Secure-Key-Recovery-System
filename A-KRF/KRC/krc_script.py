from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os
import time
import requests
import hashlib
import json

#========================= Setup =========================
# Initialize Flask app
app = Flask(__name__)

# Load keys
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Load KRC's private key
krc_private_key = load_private_key("krc_private_key.pem")

# Load Receiver's public key
receiver_public_key = load_public_key("receiver_public_key.pem")

# Load KRAs' public keys
kra_public_keys = [
    load_public_key(f"kra{i}_public_key.pem") for i in range(1, 6)
]

# Store KRA challenge verifiers
kra_challenge_verifiers = {}

# Helper funtions
def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

# Generate PKCE challenge code
def generate_pkce_challenge():
    challenge_code = os.urandom(32)
    challenge_verifier = hashlib.sha256(challenge_code).digest()
    return challenge_code, challenge_verifier

#====================== Core Functions ======================
# Function to receive and decrypt the request
def receive_and_decrypt_request(encrypted_request):
    decrypted_request = krc_private_key.decrypt(
        encrypted_request,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Decode the JSON-like structure from the request
    request = json.loads(decrypted_request.decode())
    krf = request['krf']
    requester_challenge_verifier = request['challenge_verifier']
    request_session_id = request['session_id']
    request_timestamp = request['timestamp']
    
    return krf, requester_challenge_verifier, request_session_id, request_timestamp

# Function to decrypt the KRF and validate the request
def decrypt_krf_and_validate_request(krf, request_session_id, request_timestamp):
    decrypted_krf = krc_private_key.decrypt(
        krf,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    krf_data = json.loads(decrypted_krf.decode())  # Decrypt and parse KRF
    # Session validation
    krf_session_id = krf_data['session_id']
    krf_timestamp = krf_data['timestamp']
    
    # Validate session ID and timestamp (10 min threshold)
    if krf_session_id != request_session_id or abs(request_timestamp - krf_timestamp) > 600:
        raise ValueError("Invalid session or expired request.")
    
    return krf_data

# Verify the requester using PKCE-like challenge <-useful?
def verify_requester(challenge_code, requester_challenge_verifier):
    hashed_challenge_code = hashlib.sha256(challenge_code).digest()
    if hashed_challenge_code != requester_challenge_verifier:
        raise ValueError("Challenge verification failed.")
    return "Requester verified successfully."

#====================== Key Recovery Process ======================
# Function to distribute KRF-i and perform PKCE-like challenge with KRAs
def distribute_krf_to_kras(krf, kra_public_keys):
    encrypted_krf_i_list = []
    
    # Distribute KRF-i and perform PKCE-like challenge
    for i, kra_public_key in enumerate(kra_public_keys):
        try:
            # Generate challenge for each KRA
            challenge_code, challenge_verifier = generate_pkce_challenge()
            kra_challenge_verifiers[f"KRA-{i}"] = challenge_verifier  # Store verifier for validation later

            # Send the challenge code to KRA-i
            send_to_kra(i, kra_public_key.encrypt(
                challenge_code,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ))

            # Wait for the challenge verifier from KRA-i
            kra_response = receive_from_kra(i)
            kra_challenge_verifier = kra_response["challenge_verifier"]

            # Compare challenge verifiers
            if kra_challenge_verifier != challenge_verifier:
                print(f"KRA-{i} verification failed.")
                handle_failed_kra(i)  # Handle failure scenario
                continue

            # If KRA verification succeeds, send KRF-i to KRA
            krf_i = krf[f"KRF-{i}"]
            send_to_kra(i, krf_i)

            # Wait for KRA to return the KRF-i decrypted and re-encrypted with KRC's public key
            encrypted_krf_i = receive_from_kra(i)
            encrypted_krf_i_list.append(encrypted_krf_i)  # Collect the encrypted KRF-i part
            
        except Exception as e:
            print(f"Error communicating with KRA-{i}: {str(e)}")
            handle_failed_kra(i)

    # Check if all KRF-i parts are collected
    if len(encrypted_krf_i_list) != len(kra_public_keys):
        print("Not all KRF-i parts were collected, initiating failure handling.")
        handle_kra_failure()  # Handle recovery for missing parts
    
    return encrypted_krf_i_list


# Collect key shares from KRAs and assemble session key
def collect_key_shares_and_assemble(encrypted_krf_i_list):
    key_shares = []
    for encrypted_krf_i in encrypted_krf_i_list:
        # Decrypt KRF_i
        krf_i = krc_private_key.decrypt(
            encrypted_krf_i,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        krf_i_data = json.loads(krf_i.decode())
        key_shares.append(krf_i_data["Si"])
    
    # Assemble session key using XOR of all key shares
    session_key = key_shares[0]
    for share in key_shares[1:]:
        session_key = xor(session_key, share)
    
    return session_key

# Encrypt the session key for the receiver and return it
def encrypt_and_send_session_key(session_key):
    encrypted_session_key = receiver_public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    # Send the encrypted session key back to the receiver (not implemented)
    return encrypted_session_key

#====================== Utility Functions ======================

# Utility functions (placeholders) for communication with KRAs
def send_to_kra(kra_index, encrypted_data):
    url = f"http://kra-{kra_index}:5003/process"
    response = requests.post(url, json={"encrypted_data": encrypted_data.hex()})
    if response.status_code != 200:
        raise ValueError(f"Failed to send data to KRA-{kra_index}")
    return response.json()

def receive_from_kra(kra_index):
    url = f"http://kra-{kra_index}:5003/retrieve"
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError(f"Failed to receive data from KRA-{kra_index}")
    return response.json()

# Function to handle individual KRA failures
def handle_failed_kra(i):
    print(f"Handling failure for KRA-{i}. Retrying...")
    # Retry mechanism or log failure for recovery later
    # You can implement a limited retry mechanism or fallback
    pass

# Function to handle failure in the overall KRA key shares collection
def handle_kra_failure():
    print("Handling overall KRA failure for missing KRF-i parts.")
    # Fallback mechanism for missing parts or initiate recovery process
    # Implement SFM-KRS specific recovery (e.g., redundant shares or recovery mechanism)
    pass

@app.route('/receive_request', methods=['POST'])
def receive_request():
    data = request.get_json()
    encrypted_request = bytes.fromhex(data['encrypted_request'])

    try:
        # Step 1: Receive and decrypt the request
        krf, requester_challenge_verifier, request_session_id, request_timestamp = receive_and_decrypt_request(encrypted_request)
        krf_data = decrypt_krf_and_validate_request(krf, request_session_id, request_timestamp)

        # Step 2: Distribute KRF-i to KRAs and collect encrypted KRF-i responses
        encrypted_krf_i_list = distribute_krf_to_kras(krf_data, kra_public_keys)

        # Step 3: Assemble the session key from KRF-i parts
        session_key = collect_key_shares_and_assemble(encrypted_krf_i_list)

        # Step 4: Encrypt the session key and send it back to the Receiver
        encrypted_session_key = encrypt_and_send_session_key(session_key)
        return jsonify({"status": "success", "encrypted_session_key": encrypted_session_key.hex()})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    
#========================= Main =========================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)