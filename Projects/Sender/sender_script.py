from flask import Flask, request, jsonify
import socket
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import uuid
import time
import zlib

#========================= Key Setup =========================
# Load keys directly
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Get the directory of the current script
script_dir = os.path.abspath(os.path.dirname(__file__))

# Paths for Sender's private and public keys (in the same level as script)
sender_private_key_path = os.path.join(script_dir, "keys", "sender_private.pem")
sender_public_key_path = os.path.join(script_dir, "keys", "sender_public.pem")

# Paths for Shared folder keys (parallel to the Sender folder)
shared_keys_dir = os.path.abspath(os.path.join(script_dir, "../Shared/keys"))
receiver_public_key_path = os.path.join(shared_keys_dir, "receiver_public.pem")
krc_public_key_path = os.path.join(shared_keys_dir, "krc_public.pem")

kra_public_key_paths = [
    os.path.join(shared_keys_dir, f"kra{i}_public.pem") for i in range(1, 6)
]

# # Debug print to confirm paths
# print("Sender Private Key Path:", sender_private_key_path)
# print("Sender Public Key Path:", sender_public_key_path)
# print("Receiver Public Key Path:", receiver_public_key_path)
# print("KRC Public Key Path:", krc_public_key_path)
# print("KRA Public Key Paths:", kra_public_key_paths)

# Load keys with error checking
try:
    sender_private_key = load_private_key(sender_private_key_path)
    sender_public_key = load_public_key(sender_public_key_path)

    receiver_public_key = load_public_key(receiver_public_key_path)
    krc_public_key = load_public_key(krc_public_key_path)

    kra_public_keys = [load_public_key(path) for path in kra_public_key_paths]

except FileNotFoundError as e:
    raise FileNotFoundError(f"Key file not found: {e}")

#========================= Utility Functions =========================
def compress_data(data: bytes) -> bytes:
    """Compress the given data using zlib."""
    return zlib.compress(data)

def decompress_data(data: bytes) -> bytes:
    """Decompress the given data using zlib."""
    return zlib.decompress(data)

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

    # # Encrypt the krf with the receiver public key
    # encrypted_krf = receiver_public_key.encrypt(
    #     krf,
    #     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    # )

    # !!!DELETE AFTER!!!
    encrypted_krf = krf

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
    print("Generating KRF...")
    krf = {}
    sgn = os.urandom(16)  # Shared Group Number
    num_kras = len(kra_public_keys)
    key_shares = split_session_key_xor(session_key, num_kras)  # Split session key
    timestamp = int(time.time())  # Add current timestamp

    # Include session_id and timestamp
    session_info = {"session_id": session_id, "timestamp": timestamp}
    
    try:
        encrypted_session_info = krc_public_key.encrypt(
            json.dumps(session_info).encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        krf["session_info"] = encrypted_session_info
    except Exception as e:
        print("Error encrypting session_info:", e)
        raise

    # Encrypt KRF_i for each KRA
    for i, kra_public_key in enumerate(kra_public_keys,start=1): # Start index at 1
        try:
            si = key_shares[i - 1] # Adjust for zero-based indexing
            tti = xor(si, sgn) # TTi = Si XOR SGN
            krf_i = {"Si": si.hex(), "SGN": sgn.hex(), "TTi": tti.hex()}
            krf_i_serialized = json.dumps(krf_i).encode()

            # Compress the serialized KRF-i data
            compressed_krf_i = compress_data(krf_i_serialized)

            # Encrypt with KRA public key
            krf_i_encrypted = kra_public_key.encrypt(
                compressed_krf_i,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"Size of KRF-{i} encrypted data: {len(krf_i_encrypted)} bytes")
            print("KRC Public Key Type:", type(krc_public_key))
            print("KRC Public Key Size (bits):", krc_public_key.key_size)
            print("Size of krf_i_encrypted:", len(krf_i_encrypted))
            print("Max RSA Size:", krc_public_key.key_size // 8 - 42)
            # Encrypt with KRC public key
            krf[f"KRF-{i}"] = krc_public_key.encrypt(
                krf_i_encrypted,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        except Exception as e:
            print(f"Error encrypting KRF-{i}:", e)
            raise
    print("Generated KRF:", krf)    
    return krf

# Send data to Receiver
def send_to_receiver(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('receiver', 5001))  # Use Docker service name need update here 0.0.0.0
            s.sendall(data)
            response = s.recv(1024)
        return response
    except Exception as e:
        return f"Error communicating with Receiver: {e}".encode()

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

    print(plaintext) 
    payload = 'hi'

    if not current_session["session_id"]:
        print("I'm here")
        # Perform first establishment
        session_id, session_key, encrypted_session_key, iv, encrypted_message, encrypted_krf = first_establishment(
            plaintext, receiver_public_key
        )
        print("I'm here2")
        current_session["session_id"] = session_id
        current_session["session_key"] = session_key
        print(current_session["session_id"])
        print(current_session["session_key"])
        print("session id:",session_id)
        print("encrypted key:",encrypted_session_key.hex())
        print('iv:',iv.hex())
        print("encrypt message:",encrypted_message.hex())
        print("encypt krf:",encrypted_krf)
        print("I'm here3")
        payload = {
            "session_id": session_id,
            "encrypted_session_key": encrypted_session_key.hex(),
            "iv": iv.hex(),
            "encrypted_message": encrypted_message.hex(),
            "encrypted_krf": encrypted_krf
        }
        print("Payload:", json.dumps(payload, indent=4))
    else:
        print("i'm now here at stage2")
        # Use existing session
        session_key = current_session["session_key"]
        session_id = current_session["session_id"]
        iv, encrypted_message = encrypt_plaintext(plaintext, session_key)

        payload = {
            "session_id": session_id,
            "iv": iv.hex(),
            "encrypted_message": encrypted_message.hex()
        }
        print("Payload:", json.dumps(payload, indent=4))

    # Send payload to Receiver
    response = send_to_receiver(json.dumps(payload).encode())
    return jsonify({"response": response.decode()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
