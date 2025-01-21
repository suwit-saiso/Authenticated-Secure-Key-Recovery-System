from flask import Flask, request, jsonify
import socket
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import uuid
import time

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

# Ensure a folder exists
def ensure_folder_exists(folder):
    try:
        if not os.path.exists(folder):
            os.makedirs(folder)
    except Exception as e:
        print(f"Error creating folder {folder}: {e}")

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
        print(f"  Private key -> {private_key_path}")
        print(f"  Public key -> {public_key_path}")
        print(f"  Public key (shared) -> {shared_public_key_path}")
    except Exception as e:
        print(f"Error saving keys for {entity_name}: {e}")

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

def wait_for_fresh_keys(folder, filenames, max_age_seconds=10, timeout=30):
    """
    Wait for all specified files to exist in the folder and ensure they are recently updated.
    """
    start_time = time.time()
    while True:
        all_fresh = True
        for filename in filenames:
            file_path = os.path.join(folder, filename)
            if not os.path.exists(file_path):
                all_fresh = False
                break
            modification_time = os.path.getmtime(file_path)
            if time.time() - modification_time > max_age_seconds:
                all_fresh = False
                break
        if all_fresh:
            print("All required keys are now available and fresh.")
            return
        if time.time() - start_time > timeout:
            raise TimeoutError(f"Timeout while waiting for fresh keys: {filenames}")
        time.sleep(1)

def create_restart_trigger(folder, entity_name):
    """
    Create a restart trigger file for the given entity.
    """
    trigger_path = os.path.join(folder, f"{entity_name}_restart.trigger")
    with open(trigger_path, "w") as f:
        f.write(f"Restart trigger created by {entity_name}")
    print(f"[{entity_name}] Restart trigger created: {trigger_path}")

def wait_for_no_trigger(folder, ignore_entity_name=None, timeout=30):
    """
    Wait until all trigger files are cleared or timeout occurs.
    This version allows ignoring a specific container's trigger file (e.g., the container that is restarting).
    """
    start_time = time.time()
    while True:
        triggers = [f for f in os.listdir(folder) if f.endswith(".trigger")]
        # Filter out the trigger of the container that should be ignored
        if ignore_entity_name:
            triggers = [t for t in triggers if not t.startswith(ignore_entity_name)]

        if not triggers:
            print("No trigger files detected. Proceeding...")
            return  # All triggers cleared (or ignored for the restarting container)

        if time.time() - start_time > timeout:
            raise TimeoutError(f"Timeout waiting for triggers to clear: {triggers}")

        print(f"Waiting for triggers to clear: {triggers}")
        time.sleep(1)

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
    Force clear all trigger files in the folder.
    """
    triggers = [f for f in os.listdir(folder) if f.endswith(".trigger")]
    for trigger in triggers:
        os.remove(os.path.join(folder, trigger))
    print("All triggers cleared.")
   
#========================= Utility Functions =========================
# Generate session key (AES key)
def generate_session_key():
    return os.urandom(32)  # AES 256-bit key

# Encrypt message with session key
def encrypt_plaintext(plaintext, session_key):
    print("Start encrypting plaintext.")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(plaintext.encode()) + encryptor.finalize()
    print("Encrypted plaintext successfully.")
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
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # Ensure data is padded to a multiple of block size (16 bytes for AES)
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    print("Encrypted KRF successfully.")
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
        encrypted_session_key = receiver_public_key.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception as e:
        print("Error encrypting session key:", e)
        raise

    try:
        # Encrypt the plaintext message with the session key (AES)
        iv, encrypted_message = encrypt_plaintext(plaintext, session_key)
    except Exception as e:
        print("Error encrypting plaintext message:", e)
        raise

    try:
        # Generate KRF
        krf = generate_krf(session_key, krc_public_key, keys["kra_public_keys"], receiver_public_key, session_id)
    except Exception as e:
        print("Error generating KRF:", e)
        raise

    try:
        # Generate an AES key for encrypting the KRF
        aes_key = os.urandom(32)  # AES-256 key
        iv_aes = os.urandom(16)  # IV for AES encryption
        encrypted_krf = aes_encrypt(json.dumps(krf).encode(), aes_key, iv_aes)  # Encrypt the KRF with AES
    except Exception as e:
        print("Error encrypting KRF with AES:", e)
        raise

    try:
        # Encrypt the AES key with the KRC's public key
        encrypted_aes_key = krc_public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception as e:
        print("Error encrypting AES key:", e)
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

        try:
            # Encrypt KRF-i with the KRA's public key
            krf[f"KRF-{i}"] = kra_key.encrypt(
                json.dumps(krf_i).encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).hex()
        except Exception as e:
            print(f"Error encrypting KRF-{i}:", e)
            raise

        try:
            # Encrypt TT-i with the KRC's public key
            encrypted_tti = krc_public_key.encrypt(
                tti,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            krf[f"TT-{i}"] = json.dumps({"TTi": encrypted_tti.hex()})  # Store in JSON format
        except Exception as e:
            print(f"Error encrypting TT-{i}:", e)
            raise

    # Encrypt Sr for the receiver
    try:
        encrypted_sr = receiver_public_key.encrypt(
            sr,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        krf["Sr"] = json.dumps({"Sr": encrypted_sr.hex()})  # Store in JSON format
    except Exception as e:
        print("Error encrypting Sr:", e)
        raise

    # Add session information
    try:
        other_information = {"session_id": session_id, "timestamp": timestamp}
        encrypted_info = krc_public_key.encrypt(
            json.dumps(other_information).encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        krf["OtherInformation"] = json.dumps({"Info": encrypted_info.hex()})  # Store in JSON format
    except Exception as e:
        print("Error encrypting session_info:", e)
        raise

    print(f"Generated KRF: {len(krf)} components created successfully.")
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
            s.connect((RECEIVERHOST, 5001))
            print("Connection successful, sending data...")
            s.sendall(len(data).to_bytes(4, byteorder="big") + data)
            print("Data sent, waiting for response...")
            response = s.recv(1024)
            print("Response received:", response.decode())
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
    data = request.json
    plaintext = data.get("message")

    print("Input message: ",plaintext) 
    if not current_session["session_id"]:
        print("Creating a Session...")
        # Perform first establishment
        session_id, session_key, encrypted_session_key, iv, encrypted_message, encrypted_krf, encrypted_aes_key, iv_aes = first_establishment(
            plaintext, keys["receiver_public_key"], keys["krc_public_key"]
        )
        print("Information created successfuly.")

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

    # Send payload to Receiver
    datas = json.dumps(payload).encode("utf-8")
    response = send_to_receiver(datas)
    return jsonify({"response": response.decode()})

if __name__ == "__main__":
    ENTITY_NAME = "sender"  # Replace with the container's entity name (e.g., sender, receiver, etc.)
    STARTUP_MARKER_FILE = os.path.join(SHARED_KEYS_FOLDER, f"{ENTITY_NAME}_startup.marker")  # Per-container marker
    create_restart_trigger(SHARED_KEYS_FOLDER, ENTITY_NAME)  # Notify restart

    try:
        # Step 1: Check for first-time startup
        if not os.path.exists(STARTUP_MARKER_FILE):
            print(f"[{ENTITY_NAME}] Initial startup detected. Clearing old triggers and skipping trigger wait.")
            clear_all_triggers(SHARED_KEYS_FOLDER)

            # Create a marker file to identify that startup is complete
            with open(STARTUP_MARKER_FILE, "w") as f:
                f.write("Startup complete.\n")
            print(f"[{ENTITY_NAME}] Startup marker created. Proceeding with initial setup.")
        else:
            # For subsequent runs, wait for other triggers to clear
            print(f"[{ENTITY_NAME}] Subsequent startup detected. Waiting for triggers to clear.")
            # Step 2: Wait for all other containers to clear their triggers
            wait_for_no_trigger(SHARED_KEYS_FOLDER, ignore_entity_name=ENTITY_NAME)  # Ignore this container's trigger

        # Step 3: Process and remove this container's trigger immediately
        process_trigger(SHARED_KEYS_FOLDER, ENTITY_NAME)

        # Step 4: Generate and store keys
        generate_and_store_keys(ENTITY_NAME)

        # Step 5: Define required keys
        required_keys = [
            "sender_public.pem",  # Sender's public key
            "receiver_public.pem",  # Receiver's public key
            "krc_public.pem",       # KRC's public key
        ] + [f"kra{i}_public.pem" for i in range(1, 6)]  # KRA public keys

        # Step 6: Wait for all required keys to be fresh in the shared folder
        wait_for_fresh_keys(SHARED_KEYS_FOLDER, required_keys, max_age_seconds=10, timeout=30)

        # Step 7: Load keys and store them globally
        keys = load_keys()  # Load keys after synchronization

        # Step 8: Start the container application
        app.run(host="0.0.0.0", port=5000)

    except TimeoutError as e:
        print(f"[{ENTITY_NAME}] Error: {e}")
        exit(1)
