from flask import Flask, request, jsonify
import socket
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import uuid
import time

#========================= Key Setup =========================
# Load keys directly
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Load Sender's private and public keys
sender_private_key = load_private_key("sender_private_key.pem")
sender_public_key = load_public_key("sender_public_key.pem")

# Load Receiver's public key
receiver_public_key = load_public_key("receiver_public_key.pem")

# Load KRC's public key
krc_public_key = load_public_key("krc_public_key.pem")

# Load KRAs' public keys
kra_public_keys = [
    load_public_key(f"kra{i}_public_key.pem") for i in range(1, 6)
]

#========================= Utility Functions =========================
# Generate session key (AES key)
def generate_session_key():
    return os.urandom(32)  # AES 256-bit key

# Encrypt message with session key
def encrypt_plaintext(plaintext, session_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, encrypted_message

# Encrypt session key and message for first establishment
def first_establishment(plaintext, receiver_public_key):
    session_id = str(uuid.uuid4())  # Generate a unique session ID for this communication
    session_key = generate_session_key()

    # Encrypt the session key with the receiver's public key
    encrypted_session_key = receiver_public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Encrypt the plaintext message with the session key
    iv, encrypted_message = encrypt_plaintext(plaintext, session_key)

    # Generate KRF
    krf = generate_krf(session_key, krc_public_key, kra_public_keys, session_id)

    # Encrypt the krf with the receiver public key
    encrypted_krf = receiver_public_key.encrypt(
        krf,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Package the session_id, encrypted session key, IV, and encrypted message
    return session_id, session_key, encrypted_session_key, iv, encrypted_message, encrypted_krf

# Split session key into parts for KRF
def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

def split_session_key_xor(session_key, num_parts):
    parts = [os.urandom(len(session_key)) for _ in range(num_parts - 1)]
    last_part = session_key
    for part in parts:
        last_part = xor(last_part, part)
    parts.append(last_part)
    return parts

# Generate KRF
def generate_krf(session_key, krc_public_key, kra_public_keys, session_id):
    krf = {}
    sgn = os.urandom(16)  # Shared Group Number
    num_kras = len(kra_public_keys)
    key_shares = split_session_key_xor(session_key, num_kras)  # Split session key
    timestamp = int(time.time())  # Add current timestamp

    # Include session_id and timestamp
    session_info = {"session_id": session_id, "timestamp": timestamp}
    encrypted_session_info = krc_public_key.encrypt(
        str(session_info).encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    krf["session_info"] = encrypted_session_info

    # Encrypt KRF_i for each KRA
    for i, kra_public_key in enumerate(kra_public_keys):
        si = key_shares[i]
        tti = xor(si, sgn)  # TTi = Si XOR SGN
        krf_i = {"Si": si, "SGN": sgn, "TTi": tti}
        krf_i_encrypted = kra_public_key.encrypt(
            str(krf_i).encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        krf[f"KRF-{i}"] = krc_public_key.encrypt(
            krf_i_encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    return krf

# Send data to Receiver
def send_to_receiver(data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('0.0.0.0', 5001))  # Replace with Receiver's Docker IP and port
        s.sendall(data)
        response = s.recv(1024)
    return response

#========================= Session Manager =========================
current_session = {
    "session_id": None,
    "session_key": None
}

#========================= Flask Server =========================
app = Flask(__name__)

@app.route("/send_message", methods=["POST"])
def handle_message():
    global current_session
    data = request.json
    plaintext = data.get("message")

    if not current_session["session_id"]:
        # Perform first establishment
        session_id, session_key, encrypted_session_key, iv, encrypted_message, encrypted_krf = first_establishment(
            plaintext, receiver_public_key
        )
        current_session["session_id"] = session_id
        current_session["session_key"] = session_key

        payload = {
            "session_id": session_id,
            "encrypted_session_key": encrypted_session_key.hex(),
            "iv": iv.hex(),
            "encrypted_message": encrypted_message.hex(),
            "encrypted_krf": encrypted_krf
        }
    else:
        # Use existing session
        session_key = current_session["session_key"]
        session_id = current_session["session_id"]
        iv, encrypted_message = encrypt_plaintext(plaintext, session_key)

        payload = {
            "session_id": session_id,
            "iv": iv.hex(),
            "encrypted_message": encrypted_message.hex()
        }

    # Send payload to Receiver
    response = send_to_receiver(json.dumps(payload).encode())
    return jsonify({"response": response.decode()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
