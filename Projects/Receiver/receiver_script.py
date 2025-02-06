import threading
import socket
import json
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os
import time
import hashlib
import random
import requests

#========================= Flask Server =========================
app = Flask(__name__)

#========================= Session Manager =========================
# Dictionary to store session IDs and corresponding session keys
sessions = {}

#========================= Network Setup =======================
# Socket communication setup for KRC
KRC_HOST = '192.168.1.13'  # Update with actual KRC container IP/hostname
KRC_PORT = 5002

# Socket server for sender-reciver communication to listen
LISTEN_HOST = '192.168.1.12'
LISTEN_PORT = 5001

#========================= Key Setup =========================
# Define key paths
BASE_FOLDER = os.path.dirname(os.path.abspath(__file__))  # Container's base folder
KEYS_FOLDER = os.path.join(BASE_FOLDER, "keys")
SHARED_KEYS_FOLDER = os.path.abspath(os.path.join(BASE_FOLDER, "./Shared/keys"))  # Adjust relative path

# Global variable to store keys
keys = {}

# Ensure a folder exists
def ensure_folder_exists(folder):
    try:
        if not os.path.exists(folder):
            os.makedirs(folder)
    except Exception as e:
        print(f"Error creating folder {folder}: {e}")
        send_log_to_gui(f"Error creating folder {folder}: {e}")

# Function to generate RSA Key Pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Function to save a private key to a file
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Function to save a public key to a file
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Main key generation function
def generate_and_store_keys(entity_name):
    ensure_folder_exists(KEYS_FOLDER)
    ensure_folder_exists(SHARED_KEYS_FOLDER)

    # File paths
    private_key_path = os.path.join(KEYS_FOLDER, f"{entity_name}_private.pem")
    public_key_path = os.path.join(KEYS_FOLDER, f"{entity_name}_public.pem")
    shared_public_key_path = os.path.join(SHARED_KEYS_FOLDER, f"{entity_name}_public.pem")

    # Generate key pair
    private_key, public_key = generate_rsa_key_pair()

    # Save keys
    try:
        save_private_key(private_key, private_key_path)
        save_public_key(public_key, public_key_path)
        save_public_key(public_key, shared_public_key_path)

        print(f"Keys for {entity_name} saved successfully:")
        send_log_to_gui(f"Private and public keys for {entity_name} generated and saved successfully:")
        print(f"  Private key -> {private_key_path}")
        print(f"  Public key -> {public_key_path}")
        print(f"  Public key (shared) -> {shared_public_key_path}")
    except Exception as e:
        print(f"Error saving keys for {entity_name}: {e}")
        send_log_to_gui(f"Error saving keys for {entity_name}: {e}")

# Load keys
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def load_keys():
    # Get the directory of the current script
    script_dir = os.path.abspath(os.path.dirname(__file__))

    # Paths for Receiver's private and public keys (in the same level as script)
    receiver_private_key_path = os.path.join(script_dir, "keys", "receiver_private.pem")
    receiver_public_key_path = os.path.join(script_dir, "keys", "receiver_public.pem")

    # Paths for Shared folder keys (parallel to the Sender folder)
    shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
    sender_public_key_path = os.path.join(shared_keys_dir, "sender_public.pem")
    krc_public_key_path = os.path.join(shared_keys_dir, "krc_public.pem")

    # Dictionary to hold the keys
    keys = {}

    # Load keys with error checking
    try:
        # Load receiver keys
        keys["receiver_private_key"] = load_private_key(receiver_private_key_path)
        keys["receiver_public_key"] = load_public_key(receiver_public_key_path)

        # Load shared keys
        keys["sender_public_key"] = load_public_key(sender_public_key_path)
        keys["krc_public_key"] = load_public_key(krc_public_key_path)

    except FileNotFoundError as e:
        raise FileNotFoundError(f"Key file not found: {e}")  
      
    print("Keys loaded successfully.")
    return keys

def wait_for_fresh_keys(folder, required_keys, max_age_seconds=120, timeout=60):
    """
    Wait for all required keys to appear in the shared folder and be fresh.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        all_fresh = True
        for key in required_keys:
            key_path = os.path.join(folder, key)
            if not os.path.exists(key_path):
                print(f"Missing key: {key}")
                all_fresh = False
            else:
                age = time.time() - os.path.getmtime(key_path)
                if age > max_age_seconds:
                    print(f"Stale key: {key} (age: {age} seconds)")
                    all_fresh = False
        if all_fresh:
            print("All keys are fresh.")
            send_log_to_gui("All keys are fresh.")
            return
        time.sleep(5)  # Wait before re-checking
    raise TimeoutError(f"Timeout while waiting for fresh keys: {required_keys}")

def create_restart_trigger(folder, entity_name):
    """
    Create a restart trigger file for the given entity.
    """
    trigger_path = os.path.join(folder, f"{entity_name}_restart.trigger")
    with open(trigger_path, "w") as f:
        f.write(f"Restart trigger created by {entity_name}")
    print(f"[{entity_name}] Restart trigger created: {trigger_path}")

def process_trigger(folder, entity_name):
    """
    Remove this container's restart trigger file if it exists.
    """
    trigger_path = os.path.join(folder, f"{entity_name}_restart.trigger")
    if os.path.exists(trigger_path):
        os.remove(trigger_path)
        print(f"[{entity_name}] Removed its restart trigger: {trigger_path}")
    else:
        print(f"[{entity_name}] No trigger to remove.")

def clear_all_triggers(folder):
    """
    Clear all restart trigger files in the shared folder. Ignore missing files.
    """
    for trigger in os.listdir(folder):
        if trigger.endswith("_restart.trigger"):
            try:
                os.remove(os.path.join(folder, trigger))
            except FileNotFoundError:
                # Another container might have already removed the file
                pass
    print("All triggers cleared.")

#============================= Helper funtions ===================================
def send_log_to_gui(log_message):
    """
    Send log messages to the GUI application.
    """
    gui_host = f"http://192.168.1.12"  # Adjust for GUI container's IP
    gui_port = 8001
    gui_url = f"{gui_host}:{gui_port}/new_log"
    try:
        response = requests.post(gui_url, json={"message": log_message}, timeout=5)
        if response.status_code == 200:
            print("Log successfully sent to GUI.")
        else:
            print(f"Failed to send log to GUI. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send log to GUI: {e}")

def randomized_delay(min_seconds=1, max_seconds=5):
    """Introduces a random delay to avoid race conditions during startup."""
    delay = random.uniform(min_seconds, max_seconds)
    print(f"[{ENTITY_NAME}] Randomized delay: {delay:.2f} seconds")
    time.sleep(delay)

def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

#========================= Encryption/Decryption Functions =========================
def decrypt_session_key(encrypted_session_key):    
    try:
        print(f"Attempting to decrypt session key. Length: {len(encrypted_session_key)} bytes")
        # Decrypt the session key using receiver's private key
        session_key = keys['receiver_private_key'].decrypt(
            encrypted_session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print("Decryption of session key successful!")
        send_log_to_gui("Decryption of session key successful!")
        return session_key
    except ValueError as e:
        print(f"Decryption failed: {e}")
        send_log_to_gui(f"Decryption failed: {e}")
        raise ValueError("Session key decryption failed. Ensure the correct public/private keys are used.") from e
    except Exception as e:
        print(f"Unexpected error during session key decryption: {e}")
        send_log_to_gui(f"Unexpected error during session key decryption: {e}")
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
        send_log_to_gui("Starting plaintext decryption...")
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
        plaintext_bytes = decryptor.update(encrypted_message) + decryptor.finalize()
        
        print("Decryption successful!")
        send_log_to_gui("Decryption successful!")

        # Print raw decrypted bytes before attempting to decode
        print(f"Raw decrypted bytes: {plaintext_bytes}")

        try:
            plaintext = plaintext_bytes.decode()
            return plaintext
        except UnicodeDecodeError as e:
            print("Decryption output is not valid UTF-8 text (garbage data detected).")
            send_log_to_gui("Decryption output is corrupted (garbage data detected).")
            return f"GARBAGE OUTPUT: {plaintext_bytes.hex()}"

    except ValueError as e:
        print(f"Decryption failed: {e}")
        raise ValueError("Decryption failed. Check session key, IV, and message integrity.") from e
    except Exception as e:
        print(f"Unexpected error during plaintext decryption: {e}")
        raise

def decrypt_data(encrypted_message):
    return keys["receiver_private_key"].decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_data(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

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
        send_log_to_gui("Starting recovery process.")
        
        # Generate PKCE-like challenge
        challenge_code, challenge_verifier = generate_pkce_challenge()
        timestamp = int(time.time())  # Add current timestamp
        send_log_to_gui(f"Generated challenge code: {challenge_code} and \n Challenge verifier: {challenge_verifier}")

        # Prepare key recovery request to KRC
        recovery_request = {
            'challenge_verifier': challenge_verifier.hex(),
            'session_id': session_id if isinstance(session_id, str) else session_id.hex(),
            'timestamp': timestamp
        }
        print("Recovery request prepared:", recovery_request)
        send_log_to_gui(f"Recovery request prepared: {recovery_request}")

        # Serialize and encrypt recovery request
        json_request = json.dumps(recovery_request)
        encrypted_request = encrypt_data(json_request.encode(),keys['krc_public_key'])
        payload = {
            "encrypted_request": encrypted_request.hex(),
            "encrypted_krf": encrypted_krf,
            "encrypted_AES_key": encrypted_AES_key,
            "iv_aes": iv_AES
        }
        send_log_to_gui(f"Payload to send: {payload}")

        # Send the request to KRC
        payload_bytes = json.dumps(payload).encode('utf-8')
        connection = send_to_krc(payload_bytes, False, None)
        if not connection:
            print("Failed to establish connection with KRC.")
            send_log_to_gui("Failed to establish connection with KRC.")
            return "KRC unavailable"

        # Receive initial response from KRC
        krc_response = receive_response_from_krc(connection)
        if "error" in krc_response:
            print("Error received from KRC:", krc_response["error"])
            send_log_to_gui(f"Error received from KRC: {krc_response}")
            return krc_response["error"]

        # Validate response structure
        if not isinstance(krc_response, dict) or 'response' not in krc_response:
            raise ValueError(f"Invalid response from KRC: {krc_response}")

        if krc_response.get('response') != "Request accepted, please verify yourself":
            print("Request denied by KRC.")
            send_log_to_gui("Request denied by KRC.")
            return "Request denied by KRC"

        print("Request accepted, proceeding to verification.")
        send_log_to_gui("Request accepted, proceeding to verification.")

        # Proceed with verification
        encrypted_challenge_code = encrypt_challenge_code(challenge_code, keys['krc_public_key'])

        verification_payload = {
            "encrypted_challenge_code": encrypted_challenge_code.hex()
        }
        send_log_to_gui(f"Payload to send KRF(challenge code): {verification_payload}")
        # Send verification data to KRC
        verification_bytes = json.dumps(verification_payload).encode('utf-8')
        # Reuse existing connection for verification
        connection2 = send_to_krc(verification_bytes, True, connection)
        if not connection2:
            print("Failed to reuse connection for verification.")
            send_log_to_gui("Failed to reuse connection for verification.")
            return "KRC verification failed"

        # Receive authentication response
        krc_auth_response = receive_response_from_krc(connection2)
        
        # Validate authentication response structure
        if not isinstance(krc_auth_response, dict) or 'response' not in krc_auth_response:
            raise ValueError(f"Invalid authentication response from KRC: {krc_auth_response}")

        if krc_auth_response.get('response') != "Authenticate successfully":
            print("Authentication failed.")
            send_log_to_gui("Authentication failed.")
            return "Authentication failed"

        print("Authentication successful. Waiting to receive session key parts.")
        send_log_to_gui("Authentication successful. Waiting to receive session key parts.")

        # Receive the session key parts
        key_parts = receive_from_krc(connection2)
        print("Key parts received from KRC.")

        # Validate key parts structure
        if not isinstance(key_parts, dict) or 'encrypted_unfinished_session_key' not in key_parts or 'Sr' not in key_parts:
            raise ValueError(f"Invalid key parts received from KRC: {key_parts}")

        # Decrypt the unfinished session key and Sr
        encrypted_unfinished_session_key = bytes.fromhex(key_parts['encrypted_unfinished_session_key'])
        unfinished_session_key = decrypt_data(encrypted_unfinished_session_key)

        encrypted_Sr = bytes.fromhex(key_parts['Sr'])
        Sr = decrypt_data(encrypted_Sr)
        
        send_log_to_gui(f"Key parts received from KRC.\n Unfinished session key: {unfinished_session_key} \n Requester key part: {Sr}")
        # Assemble the session key
        session_key = xor(unfinished_session_key, Sr)
        print("Session key assembly complete.")
        send_log_to_gui(f"Session key assembly complete. {session_key}")
        return session_key

    except ValueError as ve:
        print(f"Value error during recovery: {ve}")
        send_log_to_gui(f"Value error during recovery: {ve}")
        return f"Error: {ve}"
    except Exception as e:
        print(f"Unexpected error during recovery: {e}")
        send_log_to_gui(f"Unexpected error during recovery: {e}")
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
            send_log_to_gui("Data sent to KRC.")
            return s
        
        # Attempt to create a new socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(120)  # Set a 120-second timeout
        s.connect((KRC_HOST, KRC_PORT))
        s.sendall(len(data).to_bytes(4, byteorder="big") + data)
        print("Data sent to KRC.")
        send_log_to_gui("Data sent to KRC.")
        return s
    except socket.timeout:
        print("Timeout while sending data to KRC")
        send_log_to_gui("Timeout while sending data to KRC")
        return None
    except (ConnectionRefusedError, ConnectionResetError):
        print("Error: Unable to connect to KRC.")
        send_log_to_gui("Error: Unable to connect to KRC.")
        return None
    except Exception as e:
        print(f"Unexpected error in send_to_krc: {e}")
        send_log_to_gui(f"Unexpected error in send_to_krc: {e}")
        return None

# Receive response from KRC 
def receive_response_from_krc(s):
    try:
        if not s:
            raise ConnectionError("No valid socket connection to KRC.")
        
        response = s.recv(2048)
        print("Response received from KRC.")
        send_log_to_gui("Response received from KRC.")
        response_json = json.loads(response.decode())

        if not isinstance(response_json, dict):
            raise ValueError("Response is not a valid JSON object.")

        return response_json
    except socket.timeout:
        print("Timeout while waiting for response from KRC")
        send_log_to_gui("Timeout while waiting for response from KRC")
        return {"error": "Timeout"}
    except (ConnectionRefusedError, ConnectionResetError):
        print("Error: Connection issue while receiving response from KRC.")
        send_log_to_gui("Error: Connection issue while receiving response from KRC.")
        return {"error": "Connection issue"}
    except Exception as e:
        print(f"Unexpected error in receive_response_from_krc: {e}")
        send_log_to_gui(f"Unexpected error in receive_response_from_krc: {e}")
        return {"error": str(e)}

# Receive session key from KRC 
def receive_from_krc(s):
    try:
        if not s:
            raise ConnectionError("No valid socket connection to KRC.")
        
        print("Waiting to receive session key from KRC...")
        send_log_to_gui("Waiting to receive session key from KRC...")
        new_session_key = s.recv(2048)
        if not new_session_key:
            raise ValueError("No data received from KRC.")

        # Decode and parse the JSON response
        key_data = json.loads(new_session_key.decode())
        if not isinstance(key_data, dict):
            raise ValueError("Invalid format received for session key data.")

        print("Session key data successfully received from KRC.")
        send_log_to_gui("Session key data successfully received from KRC.")
        return key_data
    except socket.timeout:
        print("Timeout while waiting for session key from KRC.")
        send_log_to_gui("Timeout while waiting for session key from KRC.")
        return {"error": "Timeout"}
    except ConnectionRefusedError:
        print("Error: Connection to KRC refused.")
        send_log_to_gui("Error: Connection to KRC refused.")
        return {"error": "Connection refused"}
    except ValueError as ve:
        print(f"Data validation error: {ve}")
        send_log_to_gui(f"Data validation error: {ve}")
        return {"error": str(ve)}
    except Exception as e:
        print(f"Unexpected error in receive_from_krc: {e}")
        send_log_to_gui(f"Unexpected error in receive_from_krc: {e}")
        return {"error": str(e)}
    finally:
        if s:
            print("Closing connection after receiving session key.")
            send_log_to_gui("Closing connection after receiving session key.")
            s.close()
    
# ฟังก์ชั่นสำหรับสร้าง session ใหม่
def establish_session(session_id, session_key, encrypted_krf, iv, encrypted_message, encrypted_AES_key, iv_AES):
    sessions[session_id] = {"session_key": session_key, "krf": encrypted_krf, "iv": iv, "encrypted_message": encrypted_message, "AES_key": encrypted_AES_key, "iv_AES": iv_AES}
    print(f"Session established: {session_id}")
    sessionInfo = sessions[session_id]
    send_log_to_gui(f"Session established: {sessionInfo}")

def update_session(session_id, iv, encrypted_message):
    if session_id in sessions:
        sessions[session_id].update({"iv": iv, "encrypted_message": encrypted_message})
        print(f"Session updated: {session_id}")
        send_log_to_gui(f"Session updated: {sessions[session_id]}")
    else:
        print(f"Session ID {session_id} not found.")
        send_log_to_gui(f"Session ID {session_id} not found.")

def update_session_key(session_id,new_session_key):
    if session_id in sessions:
        sessions[session_id].update({"session_key": new_session_key})
        print(f"Session updated: {session_id}")
        send_log_to_gui(f"Session updated: {sessions[session_id]}")
    else:
        print(f"Session ID {session_id} not found.")
        send_log_to_gui(f"Session ID {session_id} not found.")

# Function to handle messages from the sender
def receive_from_sender(session_id, iv, encrypted_message):
    try:
        print("Start handling message.")
        
        # Retrieve session information
        session = sessions.get(session_id)
        if not session:
            print(f"Session not found for session_id: {session_id}")
            send_log_to_gui(f"Session not found for session_id: {session_id}")
            return {"error": "Session not found"}
        
        # Attempt to get the session key from the session
        session_key = session.get("session_key")
        
        if not session_key:
            print("Session key missing, initiating recovery.")
            send_log_to_gui("Session key missing, initiating recovery.")
            
            # Retrieve required details for session key recovery
            encrypted_krf = session.get("krf")
            encrypted_AES_key = session.get("AES_key")
            iv_AES = session.get("iv_AES")
            
            if not all([encrypted_krf, encrypted_AES_key, iv_AES]):
                print("Missing data for session key recovery.")
                send_log_to_gui("Missing data for session key recovery.")
                return {"error": "Missing data for session key recovery"}
            
            # Recover the session key
            recovered_key = recover_session_key(encrypted_krf, session_id, encrypted_AES_key, iv_AES)
            
            if recovered_key in ["Authentication failed", "Request denied"]:
                print(f"Session key recovery failed: {recovered_key}")
                send_log_to_gui(f"Session key recovery failed: {recovered_key}")
                return {"error": recovered_key}
            
            if not isinstance(recovered_key, bytes):
                print(f"Invalid session key recovered: {recovered_key}")
                send_log_to_gui(f"Invalid session key recovered: {recovered_key}")
                return {"error": "Recovered session key is invalid"}
            
            # Update session with the recovered key
            update_session_key(session_id,recovered_key)
            session["session_key"] = recovered_key
            sessions[session_id] = session  # Ensure the session is updated in the global dictionary
            print("Session key successfully recovered and stored.")
            send_log_to_gui("Session key successfully recovered and stored.")
            session_key = recovered_key
            session_key_source = "from KRC"
        else:
            session_key_source = "from sender"
        
        # Decrypt the message
        print(f"Start decrypting message using session key {session_key_source}.")
        send_log_to_gui(f"Start decrypting message using session key {session_key_source}.")
        decrypted_message = decrypt_plaintext(encrypted_message, session_key, iv)
        send_log_to_gui(f"DEBUG: {session_key}")
        print(f"Decrypted message: {decrypted_message}")
        send_log_to_gui(f"Decrypted message: {decrypted_message}\n,Session_key_used:{session_key_source}")
        
        return {
            "decrypted_message": decrypted_message,
            "session_key_used": session_key_source
        }
    
    except ValueError as ve:
        print(f"Value error during message handling: {ve}")
        return {"error": f"Value error: {ve}"}
    except Exception as e:
        print(f"Unexpected error during message handling: {e}")
        return {"error": f"Unexpected error: {e}"}

def handle_sender_connection(conn):
    global keys  # Access the global keys variable

    try:
        conn.settimeout(10)  # Set a timeout for the connection
        try:
            length = int.from_bytes(conn.recv(4), byteorder="big")
            data = conn.recv(length)
            if not data:
                print("No data received.")
                return
            print("data received")
            send_log_to_gui("data received")
            # Convert data bytes to dict
            request = json.loads(data.decode("utf-8"))

            # update key
            keys = load_keys()

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
        send_log_to_gui("Extracted data successfully.")

        # Handle session establishment or recovery
        if session_id not in sessions:
            print("Establishing new session...")
            send_log_to_gui("Establishing new session...")
            if not encrypted_krf:
                print("Missing 'encrypted_krf' for session establishment.")
                send_log_to_gui("Missing 'encrypted_krf' for session establishment.")
                conn.sendall(json.dumps({"error": "Missing 'encrypted_krf'"}).encode())
                return

            session_key = decrypt_session_key(encrypted_session_key)
            establish_session(session_id, session_key, encrypted_krf, iv, encrypted_message, encrypted_AES_key, iv_AES)
            print("Session established.")
            send_log_to_gui("Session established.")

        # Process message
        print("Processing message...")
        update_session(session_id, iv, encrypted_message)
        response = receive_from_sender(session_id, iv, encrypted_message)

        conn.sendall(json.dumps(response).encode())

    except Exception as e:
        print(f"Error handling sender connection: {e}")
        conn.sendall(json.dumps({"error": str(e)}).encode())
    finally:
        conn.close()
        print("Connection closed.")
        send_log_to_gui("Connection closed.")

# Function to start the socket server
def start_socket_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((LISTEN_HOST, LISTEN_PORT))
        server.listen(5)
        print(f"Socket server listening on {LISTEN_HOST}:{LISTEN_PORT}")
        send_log_to_gui(f"Socket server listening on {LISTEN_HOST}:{LISTEN_PORT}")

        while True:
            print("Waiting for a connection...")
            send_log_to_gui("Waiting for a connection...")
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
            send_log_to_gui("No session found")
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
            send_log_to_gui("Session key already removed")

        # Call receive_from_sender to trigger recovery
        iv = session["iv"]
        encrypted_message = session["encrypted_message"]
        response = receive_from_sender(latest_session_id, iv, encrypted_message)
        
        # Restore the session key to avoid disrupting normal operations
        if "session_key_used" in response:
            if session_key:
                send_log_to_gui("DEBUGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")
                session["session_key"] = session_key  # Restore the session key properly
                sessions[latest_session_id] = session  # Ensure session dictionary is updated

        return jsonify({"message": response})

    elif data.get("command") == "corrupt":
        if not sessions:
            print("No session found")
            send_log_to_gui("No session found")
            return jsonify({"message": "No session found"}), 404

        # Take the latest session_id
        latest_session_id = list(sessions.keys())[-1]
        session = sessions.get(latest_session_id)

        if not session:
            return jsonify({"message": "No active session found"}), 404
        
        # Simulate corrupt session key
        session["session_key"] = os.urandom(32)  # Replace with a random 32-byte key
        key = session["session_key"]
        print("Session key corrupted")
        send_log_to_gui(f"Session key corrupted. Current session key is: {key}")

        # Call receive_from_sender to trigger recovery
        iv = session["iv"]
        encrypted_message = session["encrypted_message"]
        response = receive_from_sender(latest_session_id, iv, encrypted_message)

        return jsonify({"message": response})

    return jsonify({"message": "Invalid command"}), 400

# Run Flask app and socket server concurrently
if __name__ == '__main__':
    ENTITY_NAME = "receiver"  # Replace with the container's entity name (e.g., sender, receiver, krc, kra1, etc.)
    STARTUP_MARKER_FILE = os.path.join(SHARED_KEYS_FOLDER, f"{ENTITY_NAME}_startup.marker")  # Per-container marker

    # Introduce a random delay to avoid race conditions
    randomized_delay(1, 5)

    create_restart_trigger(SHARED_KEYS_FOLDER, ENTITY_NAME)  # Notify restart
    freshstart = False

    try:
        # Step 1: Check for first-time startup
        if not os.path.exists(STARTUP_MARKER_FILE):
            print(f"[{ENTITY_NAME}] Initial startup detected. Clearing old triggers and skipping trigger wait.")
            clear_all_triggers(SHARED_KEYS_FOLDER)

            freshstart = True
            # Create a marker file to identify that startup is complete
            with open(STARTUP_MARKER_FILE, "w") as f:
                f.write("Startup complete.\n")
            print(f"[{ENTITY_NAME}] Startup marker created. Proceeding with initial setup.")
        else:
            print(f"[{ENTITY_NAME}] Restart detected. Skipping trigger and fresh key waits.")

        # Step 2: Process and remove this container's trigger immediately
        process_trigger(SHARED_KEYS_FOLDER, ENTITY_NAME)

        # Step 3: Generate and store keys
        generate_and_store_keys(ENTITY_NAME)

        # Step 4: Define required keys
        required_keys = [
            "sender_public.pem",  # Sender's public key
            "receiver_public.pem",  # Receiver's public key
            "krc_public.pem",       # KRC's public key
        ] + [f"kra{i}_public.pem" for i in range(1, 6)]  # KRA public keys

        # Step 5: Wait for all required keys to be fresh in the shared folder
        if freshstart:
            wait_for_fresh_keys(SHARED_KEYS_FOLDER, required_keys, max_age_seconds=120, timeout=60)
        
        # Step 6: Load keys and store them globally
        keys = load_keys()  # Load keys after synchronization

        # Step 7: Start the container application
        threading.Thread(target=start_socket_server, daemon=True).start()
        app.run(host='0.0.0.0', port=5050)

    except TimeoutError as e:
        print(f"[{ENTITY_NAME}] Error: {e}")
        exit(1)