import threading
import socket
import json
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os
import time
import hashlib

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

#========================= Setup =========================
# Load Receiver's private key and public key
receiver_private_key = load_private_key("receiver_private_key.pem")
receiver_public_key = load_public_key("receiver_public_key.pem")

# Load Sender's public key
sender_public_key = load_public_key("sender_public_key.pem")

# Load KRC's public key
krc_public_key = load_public_key("krc_public_key.pem")

# Dictionary to store session IDs and corresponding session keys
sessions = {}

# Socket communication setup for KRC
KRC_HOST = '0.0.0.0'  # Update with actual KRC container IP/hostname
KRC_PORT = 5002

# Socket server for sender communication
SENDER_HOST = '0.0.0.0'
SENDER_PORT = 5000

#========================= Encryption/Decryption Functions =========================
def decrypt_session_key(encrypted_session_key):
    # Decrypt the session key using receiver's private key
    session_key = receiver_private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return session_key

def encrypt_plaintext(plaintext, session_key):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    
    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    
    # Pad the plaintext before encryption (if needed)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    
    # Encrypt the padded plaintext
    encrypted_message = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return iv, encrypted_message

# Decrypt the ciphertext using the session key (AES)
def decrypt_plaintext(encrypted_message, session_key, iv):
    # Create an AES cipher object for decryption
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    decrypted_padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Remove padding from the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

# Generate PKCE challenge code
def generate_pkce_challenge():
    challenge_code = os.urandom(32)
    challenge_verifier = hashlib.sha256(challenge_code).digest()
    return challenge_code, challenge_verifier

# Encrypt challenge code with KRC's public key
def encrypt_challenge_code(challenge_code, krc_public_key):
    # Encrypt the challenge code with KRC's public key
    encrypted_challenge_code = krc_public_key.encrypt(
        challenge_code, # No need to encode since already in bytes format
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    return encrypted_challenge_code

def recover_session_key(krf,session_id):
    # Generate PKCE-like challenge
    challenge_code, challenge_verifier = generate_pkce_challenge()
    
    # Add current timestamp
    timestamp = time.time()  
    
    # Prepare key recovery request to KRC
    recovery_request = {
        'krf': krf,
        'challenge_verifier': challenge_verifier,
        'session_id':session_id,
        'timestamp': timestamp
        # Include any other necessary information
    }
    
    # Encrypt the recovery request with KRC's public key
    encrypted_request = krc_public_key.encrypt(
        str(recovery_request).encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Send the encrypted request to the KRC (implementation of send_to_krc needed)
    send_to_krc(encrypted_request)

    # Simulate receiving response from KRC
    response = receive_response_from_krc()
    if response == "Request accepted, please verify yourself":
        # Encrypt the challenge code to verify identity with KRC
        encrypted_challenge_code = encrypt_challenge_code(challenge_code, krc_public_key)
        send_to_krc(encrypted_challenge_code)
        
        # Receive the response from KRC
        auth_response = receive_response_from_krc()
        if auth_response == "Authenticate successfully":
            encrypted_session_key = receive_from_krc()  # Receive the session key from KRC
            # Decrypt the session key using receiver's private key
            session_key = receiver_private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            sessions[session_id]['session_key'] = session_key
            return session_key
        else:
            return "Authentication failed"
    else:
        return "Request denied"

# Send encrypted data to KRC (Placeholder function)
def send_to_krc(data):
     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KRC_HOST, KRC_PORT))
        s.sendall(json.dumps(data).encode())

# Receive response from KRC (Placeholder function)
def receive_response_from_krc():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KRC_HOST, KRC_PORT))
        response = s.recv(1024)
        return json.loads(response.decode())

# Receive session key from KRC (Placeholder function)
def receive_from_krc():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KRC_HOST, KRC_PORT))
        new_session_key = s.recv(1024)
        return new_session_key
    
# ฟังก์ชั่นสำหรับสร้าง session ใหม่
def establish_session(session_id, session_key, krf, iv, encrypted_message):
    sessions[session_id] = {"session_key": session_key, "krf": krf, "iv": iv, "encrypted_message": encrypted_message}
    print(f"Session established: {session_id}")

# Function to handle messages from the sender
def receive_from_sender(session_id, iv, encrypted_message):
    session = sessions.get(session_id)
    if not session:
        return "Session not found"

    session_key = session.get("session_key")
    if not session_key:
        print("Session key missing, initiating recovery")
        krf = session.get("krf")
        recovered_key = recover_session_key(krf, session_id)

        if recovered_key in ["Authentication failed", "Request denied"]:
            return f"Error: {recovered_key}"

        session["session_key"] = recovered_key
        decrypted_message = decrypt_plaintext(encrypted_message, recovered_key, iv)
        print(f"Decrypted message: {decrypted_message}")
        return {"decrypted_message": decrypted_message, "session_key_used": "from KRC"}

    # Decrypt with existing session key
    decrypted_message = decrypt_plaintext(encrypted_message, session_key, iv)
    print(f"Decrypted message: {decrypted_message}")
    return {"decrypted_message": decrypted_message, "session_key_used": "from sender"}

# Function to handle incoming data from the sender via socket
def handle_sender_connection(conn):
    try:
        data = conn.recv(4096).decode()
        if not data:
            return

        request = json.loads(data)
        session_id = request.get('session_id')
        encrypted_session_key = request.get('encrypted_session_key', None)
        encrypted_message = request.get('encrypted_message')
        iv = request.get('iv')
        encrypted_krf = request.get('krf', None)

        # Handle session establishment or recovery
        if session_id not in sessions:
            # Create a new session if session_id does not exist
            session_key = decrypt_session_key(encrypted_session_key)
            if encrypted_krf:
                krf = receiver_private_key.decrypt(
                    encrypted_krf,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                establish_session(session_id, session_key, krf, iv, encrypted_message)

        # Process message
        response = receive_from_sender(session_id, iv, encrypted_message)
        conn.sendall(json.dumps(response).encode())

    except Exception as e:
        print(f"Error handling sender connection: {e}")
        conn.sendall(json.dumps({"error": str(e)}).encode())
    finally:
        conn.close()

# Function to start the socket server
def start_socket_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((SENDER_HOST, SENDER_PORT))
        server.listen(5)
        print(f"Socket server listening on {SENDER_HOST}:{SENDER_PORT}")

        while True:
            conn, addr = server.accept()
            print(f"Connection from {addr}")
            threading.Thread(target=handle_sender_connection, args=(conn,)).start()

# Flask endpoint for manual testing
@app.route('/manual_test', methods=['POST'])
def manual_test():
    data = request.json
    if data.get("command") == "start test":
        if not sessions:
            print("No session found")
            return jsonify({"message": "No session found"}), 404

        # Take the latest session_id
        latest_session_id = list(sessions.keys())[-1]
        session = sessions[latest_session_id]

        # Simulate session key loss
        session_key = session.pop("session_key", None)
        if not session_key:
            print("Session key already removed")

        # Call receive_from_sender to trigger recovery
        iv = session["iv"]
        encrypted_message = session["encrypted_message"]
        response = receive_from_sender(latest_session_id, iv, encrypted_message)
        return jsonify({"message": response})
    return jsonify({"message": "Invalid command"}), 400

# Run Flask app and socket server concurrently
if __name__ == '__main__':
    threading.Thread(target=start_socket_server, daemon=True).start()
    app.run(host='0.0.0.0', port=5001)