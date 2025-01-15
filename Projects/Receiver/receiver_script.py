import threading
import socket
import json
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os
import time
import hashlib
# import uuid

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
shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
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
KRC_HOST = '192.168.1.13'  # Update with actual KRC container IP/hostname
KRC_PORT = 5002

# Socket server for sender-reciver communication to listen
LISTEN_HOST = '192.168.1.12'
LISTEN_PORT = 5001

#========================= Encryption/Decryption Functions =========================
def decrypt_session_key(encrypted_session_key):    
    try:
        print(f"Attempting to decrypt session key. Length: {len(encrypted_session_key)} bytes")
        # Decrypt the session key using receiver's private key
        session_key = receiver_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print("Decryption of session key successful!")
        return session_key
    except ValueError as e:
        print(f"Decryption failed: {e}")
        raise ValueError("Session key decryption failed. Ensure the correct public/private keys are used.") from e
    except Exception as e:
        print(f"Unexpected error during session key decryption: {e}")
        raise

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
    try:
        print("Starting plaintext decryption...")
        print(f"Encrypted message length: {len(encrypted_message)} bytes")
        print(f"IV length: {len(iv)} bytes")

        # Ensure IV is in bytes
        if isinstance(iv, str):
            print("IV provided as a hex string; converting to bytes.")
            iv = bytes.fromhex(iv)

        # Create an AES cipher object for decryption
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        
        # Decrypt the message
        plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
        print("Decryption successful!")
        return plaintext.decode()
    except ValueError as e:
        print(f"Decryption failed: {e}")
        raise ValueError("Decryption failed. Check session key, IV, and message integrity.") from e
    except Exception as e:
        print(f"Unexpected error during plaintext decryption: {e}")
        raise

def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

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

def recover_session_key(encrypted_krf, session_id, encrypted_AES_key, iv_AES):
    try:
        print("Starting recovery process.")
        
        # Generate PKCE-like challenge
        challenge_code, challenge_verifier = generate_pkce_challenge()
        timestamp = int(time.time())  # Add current timestamp
        
        # Prepare key recovery request to KRC
        recovery_request = {
            'challenge_verifier': challenge_verifier.hex(),
            'session_id': session_id if isinstance(session_id, str) else session_id.hex(),
            'timestamp': timestamp
        }
        print("Recovery request prepared:", recovery_request)

        # Serialize and encrypt recovery request
        json_request = json.dumps(recovery_request)
        encrypted_request = krc_public_key.encrypt(
            json_request.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        print("Preparing request payload...")
        payload = {
            "encrypted_request": encrypted_request.hex(),
            "encrypted_krf": encrypted_krf,
            "encrypted_AES_key": encrypted_AES_key,
            "iv_aes": iv_AES
        }

        # Send the request to KRC
        payload_bytes = json.dumps(payload).encode('utf-8')
        connection = send_to_krc(payload_bytes, False, None)

        # Receive initial response from KRC
        krc_response = receive_response_from_krc(connection)
        print("First response from KRC:", krc_response)

        # Validate response structure
        if not isinstance(krc_response, dict) or 'response' not in krc_response:
            raise ValueError(f"Invalid response from KRC: {krc_response}")

        response = krc_response['response']
        if response != "Request accepted, please verify yourself":
            print("Request denied by KRC:", response)
            return f"Error: {response}"

        print("Request accepted, proceeding to verification.")

        # Encrypt the challenge code for verification
        encrypted_challenge_code = encrypt_challenge_code(challenge_code, krc_public_key)

        verification_payload = {
            "encrypted_challenge_code": encrypted_challenge_code.hex()
        }

        # Send verification data to KRC
        verification_bytes = json.dumps(verification_payload).encode('utf-8')
        connection2 = send_to_krc(verification_bytes, True, connection)

        # Receive authentication response
        krc_auth_response = receive_response_from_krc(connection2)
        print("Authentication response from KRC:", krc_auth_response)

        # Validate authentication response structure
        if not isinstance(krc_auth_response, dict) or 'response' not in krc_auth_response:
            raise ValueError(f"Invalid authentication response from KRC: {krc_auth_response}")

        auth_response = krc_auth_response['response']
        if auth_response != "Authenticate successfully":
            print("Authentication failed:", auth_response)
            return f"Error: {auth_response}"

        print("Authentication successful. Waiting to receive session key parts.")

        # Receive the session key parts
        key_parts = receive_from_krc(connection2)
        print("Key parts received from KRC.")

        # Validate key parts structure
        if not isinstance(key_parts, dict) or 'encrypted_unfinished_session_key' not in key_parts or 'Sr' not in key_parts:
            raise ValueError(f"Invalid key parts received from KRC: {key_parts}")

        # Decrypt the unfinished session key and Sr
        encrypted_unfinished_session_key = bytes.fromhex(key_parts['encrypted_unfinished_session_key'])
        unfinished_session_key = receiver_private_key.decrypt(
            encrypted_unfinished_session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        encrypted_Sr = bytes.fromhex(key_parts['Sr'])
        Sr = receiver_private_key.decrypt(
            encrypted_Sr,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Assemble the session key
        session_key = xor(unfinished_session_key, Sr)
        print("Session key assembly complete.")
        return session_key

    except ValueError as e:
        print(f"Value error: {e}")
        return f"Error: {e}"
    except Exception as e:
        print(f"Unexpected error: {e}")
        return f"Error: {e}"

# Session Cleanup
def cleanup_sessions():
    current_time = int(time.time())
    expired_sessions = [session_id for session_id, session in sessions.items() if current_time - session.get("timestamp", current_time) > 3600]
    for session_id in expired_sessions:
        del sessions[session_id]
        print(f"Session {session_id} expired and removed.")

# Send encrypted data to KRC
def send_to_krc(data,have_connection,s):
    try:
        if have_connection and s:
            s.sendall(len(data).to_bytes(4, byteorder="big") + data)
            print("Data sent to KRC.")
            return s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(120)  # Set a 120-second timeout
        s.connect((KRC_HOST, KRC_PORT))
        s.sendall(len(data).to_bytes(4, byteorder="big") + data)
        print("Data sent to KRC.")
        return s
    except socket.timeout:
        print("Timeout while sending data to KRC")
    except ConnectionRefusedError:
        print("Error: Connection refused.")
    except Exception as e:
        print(f"Error in send_to_krc: {e}")

# Receive response from KRC 
def receive_response_from_krc(s):
    try:
        response = s.recv(2048)
        print("Response received from KRC.")
        return json.loads(response.decode())
    except socket.timeout:
        print("Timeout while waiting for response from KRC")
        return {"error": "Timeout"}
    except ConnectionRefusedError:
        print("Error: Connection refused.")
        return {"error": "Connection refused"}
    except Exception as e:
        print(f"Error in receive_response_from_krc: {e}")
        return {"error": str(e)}

# Receive session key from KRC 
def receive_from_krc(s):
    try:
        new_session_key = s.recv(2048)
        return json.loads(new_session_key.decode())
    except socket.timeout:
        print("Timeout while waiting for session key from KRC")
        return None
    except ConnectionRefusedError:
        print("Error: Connection refused.")
        return None
    except Exception as e:
        print(f"Error in receive_from_krc: {e}")
        return None
    finally:
        if s:
            print("Closing connection after receiving session key.")
            s.close()
    
# ฟังก์ชั่นสำหรับสร้าง session ใหม่
def establish_session(session_id, session_key, encrypted_krf, iv, encrypted_message, encrypted_AES_key, iv_AES):
    sessions[session_id] = {"session_key": session_key, "krf": encrypted_krf, "iv": iv, "encrypted_message": encrypted_message, "AES_key": encrypted_AES_key, "iv_AES": iv_AES}
    print(f"Session established: {session_id}")

# Function to handle messages from the sender
def receive_from_sender(session_id, iv, encrypted_message):
    print("Start handling message.")
    session = sessions.get(session_id)
    if not session:
        return "Session not found"

    session_key = session.get("session_key")
    if not session_key:
        print("Session key missing, initiating recovery.")
        encrypted_krf = session.get("krf")
        encrypted_AES_key = session.get("AES_key")
        iv_AES = session.get("iv_AES")
        recovered_key = recover_session_key(encrypted_krf, session_id, encrypted_AES_key, iv_AES)

        if recovered_key in ["Authentication failed", "Request denied"]:
            print("Recover failed")
            return f"Error: {recovered_key}"

        session["session_key"] = recovered_key
        print("Start decrypting message using given recovered session key.")
        decrypted_message = decrypt_plaintext(encrypted_message, recovered_key, iv)
        print(f"Decrypted message: {decrypted_message}")
        print("session_key_used: from KRC")
        return {"decrypted_message": decrypted_message, "session_key_used": "from KRC"}

    # Decrypt with existing session key
    print("Start decrypting message using given session key.")
    decrypted_message = decrypt_plaintext(encrypted_message, session_key, iv)
    print(f"Decrypted message: {decrypted_message}")
    print("session_key_used: from sender")
    return {"decrypted_message": decrypted_message, "session_key_used": "from sender"}

def handle_sender_connection(conn):
    try:
        conn.settimeout(10)  # Set a timeout for the connection
        try:
            length = int.from_bytes(conn.recv(4), byteorder="big")
            data = conn.recv(length)
            if not data:
                print("No data received.")
                return
            print("data received")
            # Convert data bytes to dict
            request = json.loads(data.decode("utf-8"))
        except socket.timeout:
            print("Connection timed out.")
            conn.sendall(json.dumps({"error": "Connection timed out"}).encode())
            conn.close()  # Explicitly close the connection
            return
        except json.JSONDecodeError as e:
            print(f"JSON decoding failed: {e}")
            conn.sendall(json.dumps({"error": "Invalid JSON format"}).encode())
            return

        # Validate required fields
        required_keys = ['session_id', 'iv', 'encrypted_message']
        for key in required_keys:
            if key not in request:
                raise ValueError(f"Missing key: {key}")

        # Extract mandatory fields
        session_id = request['session_id']
        encrypted_message = request['encrypted_message']
        iv = request['iv']

        # Extract optional fields with default values
        encrypted_session_key = request.get('encrypted_session_key', None)
        encrypted_krf = request.get('encrypted_krf', None)
        encrypted_AES_key = request.get('encrypted_AES_key', None)
        iv_AES = request.get('iv_aes', None)

        # Convert hex strings to bytes
        try:
            if isinstance(encrypted_session_key, str):
                encrypted_session_key = bytes.fromhex(encrypted_session_key)
            if isinstance(encrypted_message, str):
                encrypted_message = bytes.fromhex(encrypted_message)
        except ValueError as e:
            print(f"Hex decoding failed: {e}")
            conn.sendall(json.dumps({"error": "Invalid hex format"}).encode())
            return

        print("Extracted data successfully.")

        # Handle session establishment or recovery
        if session_id not in sessions:
            print("Establishing new session...")
            if not encrypted_krf:
                print("Missing 'encrypted_krf' for session establishment.")
                conn.sendall(json.dumps({"error": "Missing 'encrypted_krf'"}).encode())
                return

            session_key = decrypt_session_key(encrypted_session_key)
            establish_session(session_id, session_key, encrypted_krf, iv, encrypted_message, encrypted_AES_key, iv_AES)
            print("Session established.")

        # Process message
        print("Processing message...")
        response = receive_from_sender(session_id, iv, encrypted_message)

        conn.sendall(json.dumps(response).encode())

    except Exception as e:
        print(f"Error handling sender connection: {e}")
        conn.sendall(json.dumps({"error": str(e)}).encode())
    finally:
        conn.close()
        print("Connection closed.")

# Function to start the socket server
def start_socket_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((LISTEN_HOST, LISTEN_PORT))
        server.listen(5)
        print(f"Socket server listening on {LISTEN_HOST}:{LISTEN_PORT}")

        while True:
            # DELETER AFTER
            # testjsonformat()
            print("Waiting for a connection...")
            conn, addr = server.accept()
            print(f"Connection from {addr}")
            # Pass the connection to a new thread
            threading.Thread(target=handle_sender_connection, args=(conn,), daemon=True).start()

# Flask endpoint for manual testing
@app.route('/manual_test', methods=['POST'])
def manual_test():
    data = request.json
    if data.get("command") == "start test":
        if not sessions:
            # when start test before having data
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
    app.run(host='0.0.0.0', port=5050)
