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
# Get the directory of the current script
script_dir = os.path.abspath(os.path.dirname(__file__))

# Paths for Receiver's private and public keys (in the same level as script)
receiver_private_key_path = os.path.join(script_dir, "keys", "receiver_private.pem")
receiver_public_key_path = os.path.join(script_dir, "keys", "receiver_public.pem")

# Paths for Shared folder keys (parallel to the Sender folder)
shared_keys_dir = os.path.abspath(os.path.join(script_dir, "../Shared/keys"))
sender_public_key_path = os.path.join(shared_keys_dir, "sender_public.pem")
krc_public_key_path = os.path.join(shared_keys_dir, "krc_public.pem")

# Load keys with error checking
try:
    receiver_private_key = load_private_key(receiver_private_key_path)
    receiver_public_key = load_public_key(receiver_public_key_path)

    sender_public_key = load_public_key(sender_public_key_path)
    krc_public_key = load_public_key(krc_public_key_path)
except FileNotFoundError as e:
    raise FileNotFoundError(f"Key file not found: {e}")    

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
    timestamp = int(time.time())  
    
    # Prepare key recovery request to KRC
    recovery_request = {
        'krf': krf, # KRF should now be a dictionary, not a string or byte
        'challenge_verifier': challenge_verifier.hex(),  # Convert byte data to string (hex) for JSON compatibility
        'session_id':session_id,
        'timestamp': timestamp
        # Include any other necessary information
    }
    
    # Serialize recovery request to JSON
    json_request = json.dumps(recovery_request)

    # Encrypt the recovery request with KRC's public key
    encrypted_request = krc_public_key.encrypt(
        json_request.encode(),  # Encode JSON string to bytes
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Send the encrypted request to the KRC
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

# Session Cleanup
def cleanup_sessions():
    current_time = int(time.time())
    expired_sessions = [session_id for session_id, session in sessions.items() if current_time - session.get("timestamp", current_time) > 3600]
    for session_id in expired_sessions:
        del sessions[session_id]
        print(f"Session {session_id} expired and removed.")

# Send encrypted data to KRC
def send_to_krc(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Set a 10-second timeout
            s.connect((KRC_HOST, KRC_PORT))
            s.sendall(data)
    except socket.timeout:
        print("Timeout while sending data to KRC")
    except Exception as e:
        print(f"Error in send_to_krc: {e}")


# Receive response from KRC 
def receive_response_from_krc():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Set a 10-second timeout
            s.connect((KRC_HOST, KRC_PORT))
            response = s.recv(1024)
            return json.loads(response.decode())
    except socket.timeout:
        print("Timeout while waiting for response from KRC")
        return {"error": "Timeout"}
    except Exception as e:
        print(f"Error in receive_response_from_krc: {e}")
        return {"error": str(e)}

# Receive session key from KRC 
def receive_from_krc():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Set a 10-second timeout
            s.connect((KRC_HOST, KRC_PORT))
            new_session_key = s.recv(1024)
            return new_session_key
    except socket.timeout:
        print("Timeout while waiting for session key from KRC")
        return None
    except Exception as e:
        print(f"Error in receive_from_krc: {e}")
        return None
    
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
        encrypted_krf = request.get('encrypted_krf', None)
        encrypted_AES_key = request.get('encrypted_AES_key',None)
        iv_AES = request.get("iv_aes",None)

        # Handle session establishment or recovery
        if session_id not in sessions:
            # Create a new session if session_id does not exist
            session_key = decrypt_session_key(encrypted_session_key)
            if encrypted_krf:
                # Decrypting KRF
                AES_key = receiver_private_key.decrypt(
                    encrypted_AES_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                krf = decrypt_plaintext(encrypted_krf, AES_key, iv_AES)
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

#=========================== JSON payload test ======================================
def load_payload_from_file(filename="payload.json"):
    """
    Load the payload from a file.

    Args:
        filename (str): The name of the file to load the payload from. Defaults to "payload.json".

    Returns:
        dict: The loaded payload.
    """
    try:
        with open(filename, "r") as file:
            payload = json.load(file)
            # Convert hex strings back to bytes where necessary
            processed_payload = {
                key: (bytes.fromhex(value) if isinstance(value, str) and all(c in "0123456789abcdef" for c in value.lower()) else value)
                for key, value in payload.items()
            }
            return processed_payload
    except Exception as e:
        print(f"Error loading payload from file: {e}")
        raise

# Disable after TEST PHASE
payload = load_payload_from_file()
print(payload)

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
        session = sessions.get(latest_session_id)

        if not session:
            return jsonify({"message": "No active session found"}), 404
        
        # Simulate session key loss
        session_key = session.pop("session_key", None)
        if not session_key:
            print("Session key already removed")

        # Call receive_from_sender to trigger recovery
        iv = session["iv"]
        encrypted_message = session["encrypted_message"]
        response = receive_from_sender(latest_session_id, iv, encrypted_message)
        
        # Restore the session key to avoid disrupting normal operations
        if "session_key_used" in response:
            session["session_key"] = session_key

        return jsonify({"message": response})
    return jsonify({"message": "Invalid command"}), 400

# Run Flask app and socket server concurrently
if __name__ == '__main__':
    threading.Thread(target=start_socket_server, daemon=True).start()
    app.run(host='0.0.0.0', port=5001)
