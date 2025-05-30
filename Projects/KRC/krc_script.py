import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import time
import random
import requests

#========================= Key Setup =========================
# Define key paths
BASE_FOLDER = os.path.dirname(os.path.abspath(__file__))  # Container's base folder
KEYS_FOLDER = os.path.join(BASE_FOLDER, "keys")
SHARED_KEYS_FOLDER = os.path.abspath(os.path.join(BASE_FOLDER, "./Shared/keys"))  # Adjust relative path

# Global variable to store keys
keys = {}

# Store KRA challenge verifiers
kra_challenge_verifiers = {}

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

    # Paths for KRC's private and public keys (in the same level as script)
    krc_private_key_path = os.path.join(script_dir, "keys", "krc_private.pem")
    krc_public_key_path = os.path.join(script_dir, "keys", "krc_public.pem")

    # Paths for Shared folder keys (parallel to the Sender folder)
    shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
    receiver_public_key_path = os.path.join(shared_keys_dir, "receiver_public.pem")

    kra_public_key_paths = [
        os.path.join(shared_keys_dir, f"kra{i}_public.pem") for i in range(1, 6)
    ]

    # Dictionary to hold the keys
    keys = {}

    # Load keys with error checking
    try:
        # Load krc keys
        keys["krc_private_key"] = load_private_key(krc_private_key_path)
        keys["krc_public_key"] = load_public_key(krc_public_key_path)

        # Load shared keys
        keys["receiver_public_key"] = load_public_key(receiver_public_key_path)
        keys["kra_public_keys"] = [load_public_key(path) for path in kra_public_key_paths]

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
    gui_host = "http://192.168.1.13"  # Adjust for GUI container's IP or hostname
    gui_port = 8002  # Port the GUI is running on
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

# Generate PKCE challenge code
def generate_pkce_challenge():
    challenge_code = os.urandom(32)
    challenge_verifier = hashlib.sha256(challenge_code).digest()
    return challenge_code, challenge_verifier

def decrypt_data(encrypted_message):
    return keys["krc_private_key"].decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_data(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Decrypt the data using the AES key and iv (AES)
def decrypt_data_aes(data, AES_key, iv):
    try:
        print("Starting KRF decryption...")
        # Ensure IV is in bytes
        if isinstance(iv, str):
            print("IV provided as a hex string; converting to bytes.")
            iv = bytes.fromhex(iv)  # Convert hex string to bytes

        # Create an AES cipher object for decryption
        cipher = Cipher(algorithms.AES(AES_key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Decrypt the KRF
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        print("Decryption successful!")

        # Remove padding
        pad_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-pad_len]  # Remove padding bytes

        return decrypted_data.decode("utf-8")  # Returns a string
    except ValueError as e:
        print(f"Decryption failed: {e}")
        raise ValueError("Decryption failed. Check session key, IV, and message integrity.") from e
    except Exception as e:
        print(f"Unexpected error during plaintext decryption: {e}")
        raise

#====================== Core Functions ======================
# Function to receive and decrypt the request
def receive_and_decrypt_request(encrypted_request, encrypted_krf, encrypted_AES_key, iv_aes):
    print("Start to decrypt request.")
    send_log_to_gui("Start to decrypt request.")
    # decrypt the recovery request with KRC's privat key
    decrypted_request = decrypt_data(encrypted_request)

    # Decode the JSON-like structure from the request
    request = json.loads(decrypted_request.decode())
    requester_challenge_verifier = request['challenge_verifier']
    request_session_id = request['session_id']
    request_timestamp = request['timestamp']

    if isinstance(requester_challenge_verifier, str):
            requester_challenge_verifier = bytes.fromhex(requester_challenge_verifier)

    print("Start decrypt AES key.")
    send_log_to_gui("Start decrypt AES key.")
    # decrypt the AES key with KRC's privat key
    decrypted_AES_key = decrypt_data(encrypted_AES_key)
    send_log_to_gui(f"Aes key: {decrypted_AES_key}")

    # decrypt the KRF with AES key and iv_aes
    print("Start decrypt KRF.")
    send_log_to_gui("Start decrypt KRF.")
    krf = decrypt_data_aes(encrypted_krf, decrypted_AES_key, iv_aes)
    send_log_to_gui(f"KRF: {krf}")

    print("Finish decrypting request.")
    send_log_to_gui("Finish decrypting request.")
    return krf, requester_challenge_verifier, request_session_id, request_timestamp

# Function to decrypt the KRF and validate the request
def decrypt_krf_and_validate_request(krf, request_session_id, request_timestamp):
    try:
        # Step: Decrypt session info
        print("Starting to decrypt KRF informations.")
        send_log_to_gui("Starting to decrypt KRF informations.")
        
        # Step 1: Parse the KRF JSON
        try:
            krf = json.loads(krf)  # Convert JSON string to a dictionary
            print("KRF successfully parsed:", type(krf), krf.keys())  # Debug parsed object
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            send_log_to_gui(f"JSON parsing error: {e}")
            raise ValueError("Failed to parse KRF JSON.") from e
        
        # Step 2: Extract 'OtherInformation' and parse if necessary
        try:
            encrypted_other_info = krf["OtherInformation"]
            print("OtherInformation found:", encrypted_other_info)
            send_log_to_gui(f"OtherInformation found: {encrypted_other_info}")

            # Parse if OtherInformation is a JSON string
            if isinstance(encrypted_other_info, str):
                encrypted_other_info = json.loads(encrypted_other_info)

            if "Info" not in encrypted_other_info:
                raise KeyError("Missing 'Info' key in 'OtherInformation'.")
        except KeyError as e:
            print(f"Key error: {e}")
            send_log_to_gui(f"Key error: {e}")
            raise ValueError("Invalid KRF structure. Missing required keys.") from e
        except json.JSONDecodeError as e:
            print(f"JSON parsing error for 'OtherInformation': {e}")
            send_log_to_gui(f"JSON parsing error for 'OtherInformation': {e}")
            raise ValueError("Failed to parse 'OtherInformation' JSON.") from e

        # Step 3: Validate 'Info' hex string
        try:
            hex_string = encrypted_other_info["Info"]
            encrypted_session_info = bytes.fromhex(hex_string)
            print("Hex to bytes conversion successful!")
        except ValueError as e:
            print(f"Hex decoding error: {e}")
            send_log_to_gui(f"Hex decoding error: {e}")
            raise ValueError("Failed to decode 'Info' hex string to bytes.") from e
        
        # Step 4: Decrypt session info
        try:
            print("Attempting to decrypt session info...")
            send_log_to_gui("Attempting to decrypt session info...")
            session_info_decrypted = decrypt_data(encrypted_session_info)
            print("Decryption successful!")
            send_log_to_gui("Decryption successful!")
            session_info = json.loads(session_info_decrypted.decode())
            print("Session Info:", session_info)
            send_log_to_gui(f"Session Info: {session_info}")
        except Exception as e:
            print(f"Decryption error: {e}")
            send_log_to_gui(f"Decryption session info error: {e}")
            raise ValueError("Failed to decrypt or parse session info.") from e

        # Step 5: Validate session ID and timestamp
        try:
            krf_session_id = session_info["session_id"]
            krf_timestamp = session_info["timestamp"]

            print("Validating session and timestamp...")
            send_log_to_gui("Validating session and timestamp...")
            if krf_session_id != request_session_id or abs(request_timestamp - krf_timestamp) > 600:
                raise ValueError("Invalid session ID or expired timestamp.")
            print(f"Session ID: {krf_session_id}, Timestamp: {krf_timestamp}, validation complete.")
            send_log_to_gui(f"Session ID: {krf_session_id}, Timestamp: {krf_timestamp}, validation complete.")
        except KeyError as e:
            print(f"Key error during validation: {e}")
            send_log_to_gui(f"Key error during validation: {e}")
            raise ValueError("Session info missing required keys.") from e

        return krf

    except ValueError as e:
        print(f"Validation error: {e}")
        send_log_to_gui(f"Validation error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error during KRF decryption and validation: {e}")
        send_log_to_gui(f"Unexpected error during KRF decryption and validation: {e}")
        raise

# Verify the requester using PKCE-like challenge 
def verify_requester(challenge_code, requester_challenge_verifier):
    hashed_challenge_code = hashlib.sha256(challenge_code).digest()
    send_log_to_gui(f"Comparing hashed challenge code: {hashed_challenge_code} with requester challenge verifier: {requester_challenge_verifier}")
    if hashed_challenge_code != requester_challenge_verifier:
        raise ValueError("Challenge verification failed.")
    return "Requester verified successfully."

# Verify the requester 
def client_validation(client_socket, requester_challenge_verifier):
    try:
        # Receive data
        length = int.from_bytes(client_socket.recv(4), byteorder="big")
        data = client_socket.recv(length)
        if not data:
            print("No data received while requester validation.")
            send_log_to_gui("No data received while requester validation.")
            return

        # Parse JSON string into a Python dictionary
        data = json.loads(data.decode("utf-8"))
        
        print('Receiving data from Requester.Try to validat request')
        send_log_to_gui('Receiving data from Requester.Try to validat request')
        encrypted_challenge = bytes.fromhex(data['encrypted_challenge_code'])
        # decrypt the challenge code with KRC's privat key
        decrypted_challenge = decrypt_data(encrypted_challenge)

        print("Verifying requester with challenge code.")
        send_log_to_gui("Verifying requester with challenge code.")
        verification = verify_requester(decrypted_challenge, requester_challenge_verifier)
        if verification != "Requester verified successfully.":
            print("Authorization failed.")
            send_log_to_gui("Authorization failed.")
            return "Authorization failed."
        
        print("Authorization successfully.")
        send_log_to_gui("Authorization successfully.")
        return "Authorization successfully."
    
    except Exception as e:
        error_response = {"status": "error", "message": str(e)}
        client_socket.send(json.dumps(error_response).encode('utf-8')) 

#====================== Key Recovery Process ======================
# Function to distribute KRF-i and perform PKCE-like challenge with KRAs
def distribute_krf_to_kras(krf, kra_public_keys):
    print("Start distributing KRF-i.")
    send_log_to_gui("Start distributing KRF-i.")
    # KRF is a dict
    krf_i_list = [None] * len(kra_public_keys)  # Initialize list with None for tracking
    
    # Distribute KRF-i and perform PKCE-like challenge
    for i, kra_public_key in enumerate(kra_public_keys, start=1):
        try:
            print(f"prepare data to send KRA-{i}")
            send_log_to_gui(f"prepare data to send KRA-{i}")
            # Prepare data
            payload_1 = {
            "type": "challenge start"
            }

            payload_json = json.dumps(payload_1)
            payload_bytes1 = payload_json.encode('utf-8')
            print("Payload size in bytes:", len(payload_bytes1))
            send_log_to_gui(f"Payload to send: {payload_1}")
            connection1 = send_to_kra(i, payload_bytes1)

            # Wait for the challenge verifier from KRA-i
            kra_response = receive_from_kra(i,connection1)
            print(f"Extracting challenge verifier from kra-{i}.")
            send_log_to_gui(f"Extracting challenge verifier from kra-{i}.")
            if kra_response["type"] != "challenge_response":
                raise ValueError(f"Unexpected response type from KRA-{i}: {kra_response.get('type')}")         

            # decrypt challenge verifier
            encrypted_kra_challenge_verifier = bytes.fromhex(kra_response["encrypted_challenge_verifier"])
            print("Decrypting challenge verifier.")
            send_log_to_gui("Decrypting challenge verifier.")
            kra_challenge_verifier = decrypt_data(encrypted_kra_challenge_verifier)

            print(f"request Kra-{i} for confirmation")
            send_log_to_gui(f"request Kra-{i} for confirmation")
            # Prepare data
            payload_1_5 = {
            "type": "challenge verify"
            }

            payload_json = json.dumps(payload_1_5)
            payload_bytes1_5 = payload_json.encode('utf-8')
            print("Payload size in bytes:", len(payload_bytes1_5))
            send_log_to_gui(f"Payload to send: {payload_1_5}")
            connection1_5 = send_to_kra(i, payload_bytes1_5)

            # Wait for the challenge code from KRA-i
            kra_response = receive_from_kra(i,connection1_5)
            print(f"Extracting challenge code from kra-{i}.")
            send_log_to_gui(f"Extracting challenge code from kra-{i}.")
            if kra_response["type"] != "challenge_response_code":
                raise ValueError(f"Unexpected response type from KRA-{i}: {kra_response.get('type')}")
            
            # decrypt challenge code
            encrypted_kra_challenge_code = bytes.fromhex(kra_response["encrypted_challenge_code"])
            print("Decrypting challenge code.")
            send_log_to_gui("Decrypting challenge code.")
            kra_challenge_code = decrypt_data(encrypted_kra_challenge_code)

            # Compare challenge verifiers
            print("Comparing challenge verifier.")
            send_log_to_gui(f"Comparing challenge verifier {kra_challenge_verifier} from KRA with \n challenge code {kra_challenge_code} from KRA")
            
            challenge_verifier = hashlib.sha256(kra_challenge_code).digest()
            if kra_challenge_verifier != challenge_verifier:
                print(f"KRA-{i} verification failed.")
                send_log_to_gui(f"KRA-{i} verification failed.")
                if not handle_failed_kra(i, payload_1):
                    print(f"KRA-{i} permanently failed. Marking index as None.")
                    send_log_to_gui(f"KRA-{i} permanently failed. Marking index as None.")
                    krf_i_list[i - 1] = None
                    continue

            # If KRA verification succeeds, send KRF-i to KRA
            print(f"KRA-{i} verification succeeds.")
            send_log_to_gui(f"KRA-{i} verification succeeds.")
            krf_i_encrypted = krf[f"KRF-{i}"] # should still be a hex string
            # Forward the encrypted data to the responsible KRA
            print(f"prepare KRF-{i} to send KRA")
            # Prepare data
            payload_2 = {
            "encrypted_krf_i": krf_i_encrypted,
            "type": "krf_retrieval"
            }

            payload_json = json.dumps(payload_2)
            payload_bytes2 = payload_json.encode('utf-8')
            print("Payload size in bytes:", len(payload_bytes2))
            send_log_to_gui(f"Payload to send: {payload_2}")
            connection2 = send_to_kra(i, payload_bytes2)

            # Wait for KRA to return the KRF-i decrypted and re-encrypted with KRC's public key
            encrypted_krf_i = receive_from_kra(i,connection2)
            print(f"Extracting KRF-{i} from KRA.")
            send_log_to_gui(f"Extracting KRF-{i} from KRA.")
            if encrypted_krf_i["type"] != "krf_response":
                raise ValueError(f"Unexpected response type from KRA-{i}: {kra_response.get('type')}")
    
            re_encrypted_krf_i = bytes.fromhex(encrypted_krf_i["encrypted_krf_i"])
            # Decrypt re_encrypted_krf_i with KRC' privat key
            print("Decrypting re-encrypted KRF-i.")
            decrypted_krf_i = decrypt_data(re_encrypted_krf_i)
            send_log_to_gui(f"Decrypting re-encrypted KRF-i: {decrypted_krf_i}")
            # Convert the decrypted KRF-i from bytes to JSON
            try:
                krf_i = json.loads(decrypted_krf_i.decode())  # Parse JSON from bytes
                print(f"KRF-{i} successfully decrypted and parsed.")
                send_log_to_gui(f"KRF-{i} successfully decrypted and parsed.")
            except json.JSONDecodeError as e:
                print(f"Error parsing decrypted KRF-{i}: {e}")
                send_log_to_gui(f"Error parsing decrypted KRF-{i}: {e}")
                krf_i = None  # Handle invalid JSON appropriately, if needed

            krf_i_list[i - 1] = krf_i  # Save the parsed JSON result at the correct index

        except Exception as e:
            print(f"Error communicating with KRA-{i}: {e}")
            send_log_to_gui(f"Error communicating with KRA-{i}: {e}")
            if not handle_failed_kra(i, None):
                print(f"KRA-{i} permanently failed due to exception. Marking index as None.")
                send_log_to_gui(f"KRA-{i} permanently failed due to exception. Marking index as None.")
                krf_i_list[i - 1] = None

    # Check if all KRF-i parts are collected
    if None in krf_i_list:
        print("Not all KRF-i parts were collected, initiating failure handling.")
        send_log_to_gui("Not all KRF-i parts were collected, initiating failure handling.")
        krf_i_list = handle_kra_failure(krf_i_list, krf)  # Handle recovery for missing parts

    print("KRF-i list successfully completed without problems.")
    send_log_to_gui("KRF-i list successfully completed without problems.")
    return krf_i_list

# Collect key shares from KRAs and assemble session key
def collect_key_shares_and_assemble(krf_i_list, expected_si_length=32):
    """
    Assembles the session key from the KRF-i list by XOR-ing all Si values.
    If any part is missing or invalid, the function returns None.
    
    Args:
        krf_i_list (list): List of KRF-i dictionaries or None values.
        expected_si_length (int): Expected byte length of each Si value.
    
    Returns:
        bytes | None: The fully assembled session key, or None if assembly fails.
    """
    key_shares = []
    error_occurred = False  # Track if any issues occur during processing

    print("Beginning key assembly.")
    send_log_to_gui("Beginning key assembly.")

    # Extract and validate Si values
    for i, krf_i in enumerate(krf_i_list):
        if krf_i is None:
            print(f"[ERROR] KRF-{i + 1} is missing. Cannot assemble session key.")
            send_log_to_gui(f"[ERROR] KRF-{i + 1} is missing. Cannot assemble session key.")
            error_occurred = True
            continue

        try:
            # Extract Si as bytes
            Si = bytes.fromhex(krf_i["Si"])
            if len(Si) != expected_si_length:
                raise ValueError(f"Invalid length for KRF-{i + 1}. Expected {expected_si_length} bytes, got {len(Si)} bytes.")
            key_shares.append(Si)
        except (KeyError, ValueError) as e:
            print(f"[ERROR] KRF-{i + 1} processing failed: {e}")
            send_log_to_gui(f"[ERROR] KRF-{i + 1} processing failed: {e}")
            error_occurred = True

    # If any errors occurred, return None
    if error_occurred or len(key_shares) < len(krf_i_list):
        print("[ERROR] Session key assembly failed due to missing or invalid KRF-i parts.")
        send_log_to_gui("[ERROR] Session key assembly failed due to missing or invalid KRF-i parts.")
        return None

    # Assemble session key using XOR
    assembled_session_key = key_shares[0]
    for share in key_shares[1:]:
        assembled_session_key = xor(assembled_session_key, share)

    print("Session key successfully assembled.")
    send_log_to_gui(f"Session key successfully assembled: {assembled_session_key}")
    return assembled_session_key

# Encrypt the session key for the receiver and return it
def encrypt_session_key(session_key):
    """
    Encrypts the session key using the receiver's public key.

    Args:
        session_key (bytes): The session key to encrypt.

    Returns:
        bytes or None: The encrypted session key, or None if the input is invalid.
    """
    if session_key is None:
        print("Error: Session key cannot be None.")
        return None
    
    encrypted_session_key = keys["receiver_public_key"].encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_session_key

#====================== Utility Functions ======================
# Utility functions for communication with KRAs
def send_to_kra(kra_index, encrypted_data):
    """
    Send data to a KRA using a socket connection.
    """
    host = f"192.168.1.{13 + int(kra_index)}"
    port = 5002 + kra_index  # Each KRA gets a unique port starting from 5003.
    
    try:
        # Create a socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.settimeout(10)  # Set a 10-second timeout
        sock.connect((host, port))  # Connect to the KRA server          
        sock.sendall(encrypted_data)
        print(f"send data to KRA-{kra_index}.")
        send_log_to_gui(f"send data to KRA-{kra_index}.")
        return sock
    except socket.timeout:
        print("Timeout while sending data to KRC")
        send_log_to_gui("Timeout while sending data to KRC")
    except Exception as e:
        print(f"Error sending to KRA-{kra_index}: {e}")
        send_log_to_gui(f"Error sending to KRA-{kra_index}: {e}")

def receive_from_kra(kra_index,sock):
    """
    Receive data from a KRA using a socket connection.
    """
    try:
        response = sock.recv(1024)
        print(f"Response received from KRA-{kra_index}.")
        send_log_to_gui(f"Response received from KRA-{kra_index}.")
        return json.loads(response.decode())
    except socket.timeout:
        print(f"Timeout while waiting for response from KRA-{kra_index}")
        send_log_to_gui(f"Timeout while waiting for response from KRA-{kra_index}")
        return {"error": "Timeout"}
    except Exception as e:
        print(f"Error receiving from KRA-{kra_index}: {e}")
        send_log_to_gui(f"Error receiving from KRA-{kra_index}: {e}")
        return {"error": str(e)}
    finally:
        if sock:
            print(f"Closing connection after receiving data from KRA-{kra_index}.")
            send_log_to_gui(f"Closing connection after receiving data from KRA-{kra_index}.")
            sock.close()
    
# Function to handle individual KRA failures
def handle_failed_kra(kra_index, payload):
    attempt = 1
    max_retries = 3

    while attempt <= max_retries:
        print(f"Retrying communication with KRA-{kra_index} (Attempt {attempt}/{max_retries})...")
        send_log_to_gui(f"Retrying communication with KRA-{kra_index} (Attempt {attempt}/{max_retries})...")

        # Send the payload to the KRA
        connection = send_to_kra(kra_index, payload)

        # Wait for the challenge verifier response from KRA
        kra_response = receive_from_kra(kra_index,connection)
        if kra_response.get("type") == "challenge_response":
            try:
                print(f"Extracting challenge verifier on attempt {attempt}...")
                send_log_to_gui(f"Extracting challenge verifier on attempt {attempt}...")
                encrypted_kra_challenge_verifier = bytes.fromhex(kra_response["encrypted_challenge_verifier"])

                # Decrypt the challenge verifier
                print(f"Decrypting challenge verifier on attempt {attempt}...")
                send_log_to_gui(f"Decrypting challenge verifier on attempt {attempt}...")
                kra_challenge_verifier = decrypt_data(encrypted_kra_challenge_verifier)

                print(f"request Kra-{kra_index} for confirmation on attempt {attempt}...")
                send_log_to_gui(f"request Kra-{kra_index} for confirmation on attempt {attempt}...")
                # Prepare data
                payload_1_5 = {
                "type": "challenge verify"
                }

                payload_json = json.dumps(payload_1_5)
                payload_bytes1_5 = payload_json.encode('utf-8')
                print("Payload size in bytes:", len(payload_bytes1_5))
                send_log_to_gui(f"Payload to send: {payload_1_5}")
                connection1_5 = send_to_kra(kra_index, payload_bytes1_5)

                # Wait for the challenge code from KRA-i
                kra_response = receive_from_kra(kra_index,connection1_5)
                print(f"Extracting challenge code from kra-{kra_index} on attempt {attempt}....")
                send_log_to_gui(f"Extracting challenge code from kra-{kra_index} on attempt {attempt}....")
                if kra_response["type"] != "challenge_response_code":
                    raise ValueError(f"Unexpected response type from KRA-{kra_index}: {kra_response.get('type')}")
                
                # decrypt challenge code
                encrypted_kra_challenge_code = bytes.fromhex(kra_response["encrypted_challenge_code"])
                print(f"Decrypting challenge code on attempt {attempt}....")
                send_log_to_gui(f"Decrypting challenge code on attempt {attempt}....")
                kra_challenge_code = decrypt_data(encrypted_kra_challenge_code)

                challenge_verifier = hashlib.sha256(kra_challenge_code).digest()    

                # Compare challenge verifiers
                print(f"Comparing challenge verifier on attempt {attempt}...")
                send_log_to_gui(f"Comparing challenge verifier on attempt {attempt}...")
                if kra_challenge_verifier == challenge_verifier:
                    print(f"KRA-{kra_index} verification succeeded.")
                    send_log_to_gui(f"KRA-{kra_index} verification succeeded.")
                    send_log_to_gui(f"Compared: {kra_challenge_verifier} from KRA with {challenge_verifier} from KRC")
                    return True  # Successfully verified
                else:
                    print(f"KRA-{kra_index} verification failed. Challenge verifiers do not match.")
                    send_log_to_gui(f"KRA-{kra_index} verification failed. Challenge verifiers do not match.")
            except Exception as e:
                print(f"Error during KRA-{kra_index} verification on attempt {attempt}: {e}")
                send_log_to_gui(f"Error during KRA-{kra_index} verification on attempt {attempt}: {e}")
        else:
            print(f"Invalid response type from KRA-{kra_index}. Expected 'challenge_response', got: {kra_response.get('type')}")
            send_log_to_gui(f"Invalid response type from KRA-{kra_index}. Expected 'challenge_response', got: {kra_response.get('type')}")

        # Increment attempt count
        attempt += 1

    # If all retries are exhausted
    print(f"KRA-{kra_index} failed after {max_retries} retries.")
    send_log_to_gui(f"KRA-{kra_index} failed after {max_retries} retries.")
    return False

# Function to handle failure in the overall KRA key shares collection
def handle_kra_failure(krf_i_list, krf):
    print("Handling overall KRA failure for missing KRF-i parts.")
    send_log_to_gui("Handling overall KRA failure for missing KRF-i parts.")

    # Step 1: Extract and validate SGN values
    sgn_values = [bytes.fromhex(krf_i["SGN"]) for krf_i in krf_i_list if krf_i is not None]

    if not sgn_values:  # Case 1: All KRF-i are missing
        print("[WARNING] All KRF-i parts are missing. Reconstruction is not possible.")
        send_log_to_gui("[WARNING] All KRF-i parts are missing. Reconstruction is not possible.")
        return krf_i_list  # Leave list as it is (with None values)

    # Count occurrences of each SGN
    sgn_counts = {}
    for sgn in sgn_values:
        sgn_counts[sgn] = sgn_counts.get(sgn, 0) + 1

    # Identify the most common SGN
    most_common_sgn = max(sgn_counts, key=sgn_counts.get)
    print(f"Most common SGN identified: {most_common_sgn.hex()} (count: {sgn_counts[most_common_sgn]})")
    send_log_to_gui(f"Most common SGN identified: {most_common_sgn.hex()} (count: {sgn_counts[most_common_sgn]})")

    # Filter out mismatched KRF-i parts
    for i, krf_i in enumerate(krf_i_list):
        if krf_i and bytes.fromhex(krf_i["SGN"]) != most_common_sgn:
            print(f"[WARNING] Mismatched SGN in KRF-{i + 1}. Marking as missing.")
            send_log_to_gui(f"[WARNING] Mismatched SGN in KRF-{i + 1}. Marking as missing.")
            krf_i_list[i] = None  # Mark mismatched KRF-i as missing

    # Step 2: Identify missing KRF-i parts
    missing_indices = [i for i, krf_i in enumerate(krf_i_list) if krf_i is None]
    print(f"Missing KRF-i indices: {missing_indices}")
    send_log_to_gui(f"Missing KRF-i indices: {missing_indices}")

    # Step 3: Recreate missing KRF-i parts
    for i in missing_indices:
        try:
            # Retrieve and decrypt the corresponding TT-i value
            outer_encrypted_TTi = krf[f"TT-{i + 1}"]  # i + 1 corresponds to KRA-1 to KRA-5
            if isinstance(outer_encrypted_TTi, str):
                print("Parsing outer_encrypted_TTi JSON.")
                outer_encrypted_TTi = json.loads(outer_encrypted_TTi)

            encrypted_TTi = bytes.fromhex(outer_encrypted_TTi["TTi"])  # Convert hex string to bytes
            TTi = decrypt_data(encrypted_TTi)

            # Debug: Verify decrypted TT-i
            print(f"Decrypted TT-{i + 1}: {TTi.hex()}")
            send_log_to_gui(f"Decrypted TT-{i + 1}: {TTi.hex()}")

            # Calculate Si using XOR
            Si = xor(most_common_sgn, TTi)  # S_i = TTi XOR SGN

            # Debug: Verify reconstructed Si
            print(f"Reconstructed S_{i + 1}: {Si.hex()}")
            send_log_to_gui(f"Reconstructed S_{i + 1}: {Si.hex()}")

            # Recreate KRF-i as a dictionary with hex strings
            recreated_krf_i = {"Si": Si.hex(), "SGN": most_common_sgn.hex()}
            print(f"Recreated KRF-{i + 1}")
            send_log_to_gui(f"Recreated KRF-{i + 1}")

            # Save the recreated KRF-i in the list
            krf_i_list[i] = recreated_krf_i
        except Exception as e:
            print(f"[ERROR] Failed to reconstruct KRF-{i + 1}: {e}")
            send_log_to_gui(f"[ERROR] Failed to reconstruct KRF-{i + 1}: {e}")

    # Step 4: Return the updated KRF-i list
    print("KRF-i list successfully completed.")
    send_log_to_gui("KRF-i list successfully completed.")
    return krf_i_list

def receive_request(client_socket):
    global keys  # Access the global keys variable
    
    try:
        # Phase 1: Receive data
        print("Receiving data...")
        send_log_to_gui("Phase 1: Receiving data...")
        length = int.from_bytes(client_socket.recv(4), byteorder="big")
        data = client_socket.recv(length)
        if not data:
            raise ValueError("No data received from client.")
        
        # Parse the received data
        data = json.loads(data.decode("utf-8"))
        print("Loaded data from requester.")
        
        # update key
        keys = load_keys()

        encrypted_request = bytes.fromhex(data.get("encrypted_request", ""))
        encrypted_krf = bytes.fromhex(data.get("encrypted_krf", ""))
        encrypted_AES_key = bytes.fromhex(data.get("encrypted_AES_key", ""))
        iv_aes = bytes.fromhex(data.get("iv_aes", ""))

        print("Beginning Phase 1: Processing request.")
        send_log_to_gui("Phase 1: Processing request.")
        krf, requester_challenge_verifier, request_session_id, request_timestamp = receive_and_decrypt_request(
            encrypted_request, encrypted_krf, encrypted_AES_key, iv_aes
        )
        krf_data = decrypt_krf_and_validate_request(krf, request_session_id, request_timestamp)

        if not krf_data:
            raise ValueError("Invalid KRF data: Request validation failed.")

        request_validation = {'response': "Request accepted, please verify yourself"}
        client_socket.send(json.dumps(request_validation).encode('utf-8'))

        # Phase 2: Validate Requester
        print("Beginning Phase 2: Validating requester.")
        send_log_to_gui("Beginning Phase 2: Validating requester.")
        authorization = client_validation(client_socket, requester_challenge_verifier)
        if authorization != "Authorization successfully.":
            raise ValueError("Requester validation failed: Authentication error.")

        requester_validation = {"response": "Authenticate successfully"}
        client_socket.send(json.dumps(requester_validation).encode('utf-8'))

        # Phase 3: Distribute KRF-i
        print("Beginning Phase 3: Distributing KRF-i.")
        send_log_to_gui("Beginning Phase 3: Distributing KRF-i.")
        krf_i_list = distribute_krf_to_kras(krf_data, keys["kra_public_keys"])

        # Phase 4: Assemble session key
        print("Beginning Phase 4: Assembling session key.")
        send_log_to_gui("Beginning Phase 4: Assembling session key.")
        unfinished_session_key = collect_key_shares_and_assemble(krf_i_list)

        # Phase 5: Encrypt and send session key
        print("Beginning Phase 5: Encrypting and sending session key.")
        send_log_to_gui("Beginning Phase 5: Encrypting and sending session key.")
        if unfinished_session_key is None:
            raise ValueError("Failed to assemble a complete session key.")

        encrypted_session_key = encrypt_session_key(unfinished_session_key)

        Sr = krf_data["Sr"]
        if isinstance(Sr, str):
            Sr = json.loads(Sr)

        encrypted_Sr = bytes.fromhex(Sr["Sr"])  # Ensure valid format
        payload = {
            "encrypted_unfinished_session_key": encrypted_session_key.hex(),
            "Sr": encrypted_Sr.hex(),
        }
        client_socket.send(json.dumps(payload).encode('utf-8'))
        print("Keys successfully sent.")
        send_log_to_gui("Key parts successfully sent.")

    except Exception as e:
        error_message = f"Error: {str(e)}"
        print(error_message)  # Log error for debugging
        error_response = {"status": "error", "message": error_message}
        try:
            client_socket.send(json.dumps(error_response).encode('utf-8'))
        except Exception as send_error:
            print(f"Failed to send error response: {send_error}")
    finally:
        print("Closing connection after finishing recovery process.")
        send_log_to_gui("Closing connection after finishing recovery process.")
        client_socket.close()

#========================= Main =========================
def main():
    KRC_PORT = 5002
    print("KRC script has started executing.")
    send_log_to_gui("KRC script has started executing.")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("192.168.1.13", KRC_PORT))
    server_socket.listen(5)
    print(f"KRC listening on port {KRC_PORT}")
    send_log_to_gui(f"KRC listening on port {KRC_PORT}")
    
    while True:
        client_socket, _ = server_socket.accept()
        receive_request(client_socket)

if __name__ == "__main__":
    ENTITY_NAME = "krc"  # Replace with the container's entity name (e.g., sender, receiver, krc, kra1, etc.)
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
        main()

    except TimeoutError as e:
        print(f"[{ENTITY_NAME}] Error: {e}")
        exit(1)