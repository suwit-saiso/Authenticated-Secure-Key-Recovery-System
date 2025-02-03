from flask import Flask, request, jsonify
import socket
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import uuid
import time
import copy
import random
import requests
import hashlib

#========================= Network Setup =======================
RECEIVERHOST = "192.168.1.12"

#========================= Session Manager =========================
current_session = {
    "session_id": None,
    "session_key": None
}

#========================= Flask Server =========================
app = Flask(__name__)

#========================= Key Setup =========================
# Define key paths
BASE_FOLDER = os.path.dirname(os.path.abspath(__file__))  # Container's base folder
KEYS_FOLDER = os.path.join(BASE_FOLDER, "keys")
SHARED_KEYS_FOLDER = os.path.abspath(os.path.join(BASE_FOLDER, "./Shared/keys"))  # Adjust relative path

# Global variable to store keys
keys = {}

# Track the previously loaded keys
previous_keys = {}

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

# Load keys directly
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def load_keys():
    # Get the directory of the current script
    script_dir = os.path.abspath(os.path.dirname(__file__))

    # Paths for Sender's private and public keys
    sender_private_key_path = os.path.join(script_dir, "keys", "sender_private.pem")
    sender_public_key_path = os.path.join(script_dir, "keys", "sender_public.pem")

    # Paths for Shared folder keys
    shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
    receiver_public_key_path = os.path.join(shared_keys_dir, "receiver_public.pem")
    krc_public_key_path = os.path.join(shared_keys_dir, "krc_public.pem")

    kra_public_key_paths = [
        os.path.join(shared_keys_dir, f"kra{i}_public.pem") for i in range(1, 6)
    ]

    # Dictionary to hold the keys
    keys = {}

    try:
        # Load sender keys
        keys["sender_private_key"] = load_private_key(sender_private_key_path)
        keys["sender_public_key"] = load_public_key(sender_public_key_path)

        # Load shared keys
        keys["receiver_public_key"] = load_public_key(receiver_public_key_path)
        keys["krc_public_key"] = load_public_key(krc_public_key_path)
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
   
def serialize_key(key):
    """Convert RSA keys to a string format for comparison."""
    if isinstance(key, bytes):  
        return key.decode("utf-8").strip()
    elif hasattr(key, "public_bytes"):  
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8").strip()
    elif hasattr(key, "private_bytes"):  
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8").strip()
    elif isinstance(key, list):  
        return [serialize_key(k) for k in key]  # Ensure consistency before hashing
    return str(key)  # Convert unknown types to string

def hash_key(key_data):
    """Generate a hash for the serialized key to compare safely."""
    if isinstance(key_data, list):
        # Convert list to a sorted string representation to ensure consistent comparison
        key_data = json.dumps(sorted(key_data))  # Convert to JSON string format

    return hashlib.sha256(key_data.encode('utf-8')).hexdigest()

def have_keys_changed(new_keys):
    """
    Compare the newly loaded keys with the previously loaded ones.
    """
    global previous_keys

    if previous_keys is None:  
        previous_keys = {}  

    # Convert RSA keys to comparable hash format
    serialized_new_keys = {k: hash_key(serialize_key(v)) for k, v in new_keys.items()}
    serialized_prev_keys = {k: hash_key(serialize_key(v)) for k, v in previous_keys.items()}

    for key_name, key_value in serialized_new_keys.items():
        if key_name not in serialized_prev_keys or serialized_prev_keys[key_name] != key_value:
            print(f"Key {key_name} has changed!")
            send_log_to_gui(f"Debugging: Key {key_name} has changed!")
            previous_keys = copy.deepcopy(new_keys)  # Update keys immediately
            return True  # A key has changed

    print("No key changes detected.")
    send_log_to_gui("Debugging: No key changes detected.")
    
    previous_keys = copy.deepcopy(new_keys)  # Ensure state is updated
    return False

#========================= Utility Functions =========================
def send_log_to_gui(log_message):
    """
    Send log messages to the GUI application.
    """
    gui_host = f"http://192.168.1.11"  # Adjust for GUI container's IP
    gui_port = 8000
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

# Generate session key (AES key)
def generate_session_key():
    return os.urandom(32)  # AES 256-bit key

def decrypt_data(encrypted_message):
    return keys["sender_private_key"].decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_data(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Encrypt message with session key
def encrypt_plaintext(plaintext, session_key):
    print("Start encrypting plaintext.")
    send_log_to_gui("Start encrypting plaintext.")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(plaintext.encode()) + encryptor.finalize()
    print("Encrypted plaintext successfully.")
    send_log_to_gui("Encrypted plaintext successfully.")
    return iv, encrypted_message

def aes_encrypt(data, key, iv):
    """
    Encrypts data using AES-256 with CBC mode.

    Args:
        data (bytes): The plaintext data to encrypt.
        key (bytes): The AES key.
        iv (bytes): The initialization vector.

    Returns:
        bytes: The encrypted data.
    """
    print("Start encrypting KRF with AES.")
    send_log_to_gui("Start encrypting KRF with AES.")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # Ensure data is padded to a multiple of block size (16 bytes for AES)
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    print("Encrypted KRF successfully.")
    send_log_to_gui("Encrypted KRF successfully.")
    return encryptor.update(padded_data) + encryptor.finalize()

# Encrypt session key and message for first establishment
def first_establishment(plaintext, receiver_public_key, krc_public_key):
    """
    Handles the first establishment of a secure communication session.

    Args:
        plaintext (str): The plaintext message to be sent.
        receiver_public_key (object): The receiver's public RSA key.

    Returns:
        tuple: Contains session_id, session_key, encrypted_session_key, iv (for message), 
               encrypted_message, encrypted_krf, encrypted_aes_key, iv_aes.
    """
    session_id = str(uuid.uuid4())  # Generate a unique session ID for this communication
    session_key = generate_session_key()  # Generate a session key for encryption

    try:
        # Encrypt the session key with the receiver's public key
        encrypted_session_key = encrypt_data(session_key,receiver_public_key)
        send_log_to_gui(f"Session id: {session_id} \n Session key: {session_key} \n Encrypted session key: {encrypted_session_key} \n successfully generated.")
    except Exception as e:
        print("Error encrypting session key:", e)
        send_log_to_gui(f"Error encrypting session key: {e}")
        raise

    try:
        # Encrypt the plaintext message with the session key (AES)
        iv, encrypted_message = encrypt_plaintext(plaintext, session_key)
        send_log_to_gui(f"Message: {plaintext} \n Encrypted text {encrypted_message}")
    except Exception as e:
        print("Error encrypting plaintext message:", e)
        send_log_to_gui(f"Error encrypting plaintext message: {e}")
        raise

    try:
        # Generate KRF
        krf = generate_krf(session_key, krc_public_key, keys["kra_public_keys"], receiver_public_key, session_id)
        send_log_to_gui(f"Generated krf: {krf}")
    except Exception as e:
        print("Error generating KRF:", e)
        send_log_to_gui(f"Error generating KRF:{e}")
        raise

    try:
        # Generate an AES key for encrypting the KRF
        aes_key = os.urandom(32)  # AES-256 key
        iv_aes = os.urandom(16)  # IV for AES encryption
        encrypted_krf = aes_encrypt(json.dumps(krf).encode(), aes_key, iv_aes)  # Encrypt the KRF with AES
        send_log_to_gui(f"Aes key: {aes_key} \n Encrypted krf: {encrypted_krf}")
    except Exception as e:
        print("Error encrypting KRF with AES:", e)
        send_log_to_gui(f"Error encrypting KRF with AES: {e}")
        raise

    try:
        # Encrypt the AES key with the KRC's public key
        encrypted_aes_key = encrypt_data(aes_key,krc_public_key)
        send_log_to_gui(f"Encrypted aes key: {encrypted_aes_key}")
    except Exception as e:
        print("Error encrypting AES key:", e)
        send_log_to_gui(f"Error encrypting AES key:{e}")
        raise

    # Package the session_id, encrypted session key, IVs, encrypted message, and KRF
    return session_id, session_key, encrypted_session_key, iv, encrypted_message, encrypted_krf, encrypted_aes_key, iv_aes

# Split session key into parts for KRF
def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

def test_assemble_krf(session_key, num_agents, si_values, sr, sgn, tti_values):
    print("\n--- Testing KRF Assembly ---")
    print(f"Session Key (Original): {session_key.hex()}")
    print("Si Values and Sr:")
    for i, si in enumerate(si_values):
        print(f"  S_{i+1}: {si.hex()} (Length: {len(si)} bytes)")
    print(f"  Sr: {sr.hex()} (Length: {len(sr)} bytes)")

    # Verify Sr calculation
    computed_sr = session_key
    for si in si_values:
        computed_sr = xor(computed_sr, si)
    print(f"Computed Sr: {computed_sr.hex()} (Length: {len(computed_sr)} bytes)")
    print("Sr Match:", computed_sr == sr)

    # Verify full session key reconstruction
    reconstructed_key = sr
    for si in si_values:
        reconstructed_key = xor(reconstructed_key, si)
    print(f"Reconstructed Session Key: {reconstructed_key.hex()} (Length: {len(reconstructed_key)} bytes)")
    print("Session Key Match:", session_key == reconstructed_key)

    # Test TTi values for Si reconstruction
    print("\n--- Testing TTi Values ---")
    print(f"SGN: {sgn.hex()} (Length: {len(sgn)} bytes)")
    for i, (tti, si) in enumerate(zip(tti_values, si_values), start=1):
        print(f"\n  Expected TTi_{i}: {tti.hex()} (Length: {len(tti)} bytes)")
        print(f"  TTi_{i}: {tti.hex()} (Length: {len(tti)} bytes)")
        print(f"  Expected Si_{i}: {si.hex()} (Length: {len(si)} bytes)")

        reconstructed_si = xor(tti, sgn)  # Reconstruct Si
        print(f"  Si_{i} (Reconstructed): {reconstructed_si.hex()} (Length: {len(reconstructed_si)} bytes)")
        si_match = reconstructed_si == si
        print(f"  Match for Si_{i}: {si_match}")

        if not si_match:
            print(f"  [ERROR] Si_{i} mismatch: Expected {si.hex()}, got {reconstructed_si.hex()}")

        # Length validation
        if len(tti) != len(sgn):
            print(f"  [ERROR] Length mismatch for TTi_{i}: TTi length is {len(tti)} bytes, SGN length is {len(sgn)} bytes")
        if len(si) != len(sgn):
            print(f"  [ERROR] Length mismatch for Si_{i}: Si length is {len(si)} bytes, SGN length is {len(sgn)} bytes")

# Generate KRF
def generate_krf(session_key, krc_public_key, kra_public_keys, receiver_public_key, session_id):
    print("Generating KRF...")
    send_log_to_gui("Generating KRF...")
    krf = {}
    num_kras = len(kra_public_keys)  # Number of KRAs (should be 5)
    timestamp = int(time.time())  # Current timestamp

    # Generate Si values for KRAs
    si_values = [os.urandom(32) for _ in range(num_kras)]
    sr = session_key  # Start with the session key
    for si in si_values:
        sr = xor(sr, si)  # Compute Sr such that XOR(Si, ..., Sr) = session_key

    # Generate Ri for SGN calculation
    ri_values = [os.urandom(32) for _ in range(num_kras + 1)]  # Include receiver
    sgn = ri_values[0]
    for ri in ri_values[1:]:
        sgn = xor(sgn, ri)  # SGN = R1 XOR R2 XOR ... Rn

    # Initialize list to store TTi values for testing
    tti_values = []

    # Construct KRF-i and TT-i for each KRA
    for i, (kra_key, si) in enumerate(zip(kra_public_keys, si_values), start=1):
        tti = xor(si, sgn)  # TTi = Si XOR SGN
        tti_values.append(tti)  # Save TTi for testing
        krf_i = {'Si': si.hex(), 'SGN': sgn.hex()}
        send_log_to_gui(f"krf-{i}: {krf_i} \n tt-{i}: tti")

        try:
            # Encrypt KRF-i with the KRA's public key
            krf[f"KRF-{i}"] = encrypt_data(json.dumps(krf_i).encode(),kra_key).hex()
            krfi = krf[f"KRF-{i}"]
            send_log_to_gui(f"Encrypted KRF-{i}: {krfi}")
        except Exception as e:
            print(f"Error encrypting KRF-{i}:", e)
            send_log_to_gui(f"Error encrypting KRF-{i}: {e}")
            raise

        try:
            # Encrypt TT-i with the KRC's public key
            encrypted_tti = encrypt_data(tti,krc_public_key)
            send_log_to_gui(f"Encrypted tt-{i}: {encrypted_tti}")
            krf[f"TT-{i}"] = json.dumps({"TTi": encrypted_tti.hex()})  # Store in JSON format
        except Exception as e:
            print(f"Error encrypting TT-{i}:", e)
            send_log_to_gui(f"Error encrypting TT-{i}: {e}")
            raise

    # Encrypt Sr for the receiver
    try:
        encrypted_sr = encrypt_data(sr,receiver_public_key)
        krf["Sr"] = json.dumps({"Sr": encrypted_sr.hex()})  # Store in JSON format
    except Exception as e:
        print("Error encrypting Sr:", e)
        send_log_to_gui(f"Error encrypting Sr: {e}")
        raise

    # Add session information
    try:
        other_information = {"session_id": session_id, "timestamp": timestamp}
        encrypted_info = encrypt_data(json.dumps(other_information).encode(),krc_public_key)
        send_log_to_gui(f"Other info: {other_information} \n Encrypted info: {encrypted_info}")
        krf["OtherInformation"] = json.dumps({"Info": encrypted_info.hex()})  # Store in JSON format
    except Exception as e:
        print("Error encrypting session_info:", e)
        send_log_to_gui(f"Error encrypting session_info: {e}")
        raise

    print(f"Generated KRF: {len(krf)} components created successfully.")
    send_log_to_gui(f"Generated KRF: {len(krf)} components created successfully.")
    # DEBUG: Test reconstruction
    # test_assemble_krf(session_key, num_kras, si_values, sr, sgn, tti_values)
    return krf

# Send data to Receiver
def send_to_receiver(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print("Creating socket...")
            s.bind(("192.168.1.11", 6000))  # Use a dynamic port
            print(f"Connecting to {RECEIVERHOST}:5001...")
            send_log_to_gui(f"Connecting to {RECEIVERHOST}:5001...")
            s.connect((RECEIVERHOST, 5001))
            print("Connection successful, sending data...")
            s.sendall(len(data).to_bytes(4, byteorder="big") + data)
            print("Data sent, waiting for response...")
            send_log_to_gui("Data sent, waiting for response...")
            response = s.recv(1024)
            print("Response received:", response.decode())
            send_log_to_gui(f"Response received: {response.decode()}")
        return response
    except socket.timeout:
        print("Error: Connection timed out.")
        return b"Error: Receiver timed out."
    except ConnectionRefusedError:
        print("Error: Connection refused.")
        return b"Error: Connection refused."
    except Exception as e:
        print(f"Socket error: {e}")
        return f"Error: {e}".encode()

@app.route("/send_message", methods=["POST"])
def handle_message():
    global current_session
    global keys,previous_keys # Access the global keys variable

    send_log_to_gui("Waiting for Input message...")
    data = request.json
    plaintext = data.get("message")
    receiveraddr = data.get("receiver", None)
    if receiveraddr:
        send_log_to_gui(f"Address for receiver: {receiveraddr} received.")

    print("Input message: ",plaintext) 
    send_log_to_gui(f"Input message: {plaintext}")

    # Update keys and check if they have changed
    new_keys = load_keys()
    keys_have_changed = have_keys_changed(new_keys)

    # Ensure previous_keys are updated after comparison
    if not keys_have_changed:
        previous_keys = new_keys  # Update the previous_keys if no changes detected

    print(f"Keys have changed: {keys_have_changed}")
    send_log_to_gui(f"Debugging: Keys have changed: {keys_have_changed}")

    # If there's no active session or keys have changed, create a new session
    if not current_session["session_id"] or keys_have_changed:
        print("Creating a Session...")
        send_log_to_gui("Creating a Session...")
        
        # update key
        keys = new_keys  # Use already loaded new_keys
        
        # Perform first establishment
        session_id, session_key, encrypted_session_key, iv, encrypted_message, encrypted_krf, encrypted_aes_key, iv_aes = first_establishment(
            plaintext, keys["receiver_public_key"], keys["krc_public_key"]
        )
        print("Information created successfuly.")
        send_log_to_gui("Session created successfuly.")

        current_session["session_id"] = session_id
        current_session["session_key"] = session_key
        
        print("beginning to prepare the payload...")
        payload = {
            "session_id": session_id,
            "encrypted_session_key": encrypted_session_key.hex(),
            "iv": iv.hex(),
            "encrypted_message": encrypted_message.hex(),
            "encrypted_krf": encrypted_krf.hex(),
            "encrypted_AES_key": encrypted_aes_key.hex(),
            "iv_aes": iv_aes.hex()
        }
        send_log_to_gui(f"Payload prepared: {payload}")
    else:
        print("sending to existing session")
        send_log_to_gui("sending to existing session")
        # Use existing session
        session_key = current_session["session_key"]
        session_id = current_session["session_id"]
        iv, encrypted_message = encrypt_plaintext(plaintext, session_key)

        payload = {
            "session_id": session_id,
            "iv": iv.hex(),
            "encrypted_message": encrypted_message.hex()
        }
        send_log_to_gui(f"Payload prepared: {payload}")

    # Send payload to Receiver
    datas = json.dumps(payload).encode("utf-8")
    response = send_to_receiver(datas)
    return jsonify({"response": response.decode()})

if __name__ == "__main__":
    ENTITY_NAME = "sender"  # Replace with the container's entity name (e.g., sender, receiver, etc.)
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
        previous_keys = keys

        # Step 7: Start the container application
        app.run(host="0.0.0.0", port=5000)

    except TimeoutError as e:
        print(f"[{ENTITY_NAME}] Error: {e}")
        exit(1)