from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import uuid
import time
import requests

app = Flask(__name__)

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
    load_public_key(f"kra_public_key_{i}.pem") for i in range(1, 6)
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
def first_establishment(session_key, plaintext, receiver_public_key):
    session_id = str(uuid.uuid4())  # Generate a unique session ID for this communication
    
    # Encrypt the session key with the receiver's public key
    encrypted_session_key = receiver_public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Encrypt the plaintext message with the session key
    iv, encrypted_message = encrypt_plaintext(plaintext, session_key)
    
    # Package the session_id, encrypted session key, IV, and encrypted message
    return session_id, encrypted_session_key, iv, encrypted_message

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
    timestamp = time.time()  # Add current timestamp

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

#========================= Flask Routes =========================
@app.route('/send', methods=['POST'])
def send_message():
    # รับ plaintext จาก client
    data = request.json
    plaintext = data['message']

     # สร้าง session key และเข้ารหัสข้อความ
    session_key = generate_session_key()

    # First establishment
    session_id, encrypted_session_key, iv, encrypted_message = first_establishment(
        session_key, plaintext, receiver_public_key)

    # Generate KRF
    krf = generate_krf(session_key, krc_public_key, kra_public_keys, session_id)

    # Send data to Receiver
    receiver_url = "http://receiver:5001/receive"
    # เตรียมข้อมูลส่งไปยัง Receiver
    payload = {
        "session_id": session_id,
        "encrypted_session_key": encrypted_session_key.hex(),
        "iv": iv.hex(),
        "encrypted_message": encrypted_message.hex(),
        "krf": {k: v.hex() for k, v in krf.items()}
    }
    # ส่งข้อมูลไปยัง Receiver
    response = requests.post(receiver_url, json=payload)
    return jsonify(response.json())

#========================= Main =========================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
