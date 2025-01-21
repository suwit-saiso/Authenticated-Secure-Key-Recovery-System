import os
import hashlib
import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from cryptography.hazmat.primitives import hashes, serialization
import time

#=================================== Network Setup ===========================================
# Dynamically determine KRA ID from the folder name or environment variable
script_dir = os.path.abspath(os.path.dirname(__file__))
KRA_ID = os.getenv("KRA_ID", os.path.basename(script_dir))  # e.g., kra1, kra2, ...

# Assign LISTEN_HOST dynamically
LISTEN_HOST = f"192.168.1.{14 + int(KRA_ID[-1]) - 1}"

# Port for the KRA (defaults to 5003, or can be set per KRA using an env variable)
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 5003 + int(KRA_ID[-1]) - 1))  # Ports 5003, 5004, etc.

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

# Load private key
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

# Load public key
def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def load_keys():
    # Get the directory of the current script (to use as base path)
    script_dir = os.path.abspath(os.path.dirname(__file__))

    # Paths for private key (within the current KRA folder) and shared public key
    private_key_path = os.path.join(script_dir, "keys", f"{KRA_ID}_private.pem")
    shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
    krc_public_key_path = os.path.join(shared_keys_dir, "krc_public.pem")

    # Dictionary to hold the keys
    keys = {}

    # Load keys with error handling
    try:
        # Load kra keys
        keys["kra_private_key"] = load_private_key(private_key_path)

        # Load shared keys
        keys["krc_public_key"] = load_public_key(krc_public_key_path)

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

def wait_for_no_trigger(folder, timeout=30):
    """
    Wait until all trigger files are cleared or a timeout occurs.
    """
    start_time = time.time()
    while True:
        triggers = [f for f in os.listdir(folder) if f.endswith(".trigger")]
        if not triggers:
            return  # No triggers, safe to proceed
        if time.time() - start_time > timeout:
            raise TimeoutError(f"Timeout waiting for triggers to clear: {triggers}")
        time.sleep(1)

def process_trigger(folder, entity_name):
    """
    Remove this entity's restart trigger file if it exists.
    """
    trigger_path = os.path.join(folder, f"{entity_name}_restart.trigger")
    if os.path.exists(trigger_path):
        os.remove(trigger_path)
        print(f"[{entity_name}] Removed its restart trigger: {trigger_path}")

def clear_all_triggers(folder):
    """
    Remove all trigger files from the folder.
    """
    triggers = [f for f in os.listdir(folder) if f.endswith(".trigger")]
    for trigger in triggers:
        os.remove(os.path.join(folder, trigger))
    print("All triggers cleared.")
    
#============================= Helper funtions ===================================
def decrypt_message(encrypted_message):
    return keys["kra_private_key"].decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_message(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def handle_client(client_socket):
    try:
        # Receive data
        data = client_socket.recv(4096).decode("utf-8")  # Convert bytes to string
        print("Loaded data from KRC:", data)
        if not data:
            print("No data received.")
            return
        
        # Parse data (assumes a simple JSON protocol) JSON string into a Python dictionary
        message = json.loads(data)

        if message["type"] == "challenge":
            print("Extract challenge code.")
            encrypted_challenge = bytes.fromhex(message["encrypted_challenge_code"])
            challenge_code = decrypt_message(encrypted_challenge)
            
            # Generate challenge verifier
            print("hashing challenge code.")
            challenge_verifier = hashlib.sha256(challenge_code).digest()
            
            # Encrypt verifier with KRC's public key
            print("Encrypting challenge.")
            encrypted_verifier = encrypt_message(challenge_verifier, keys["krc_public_key"])
            response = {
                "type": "challenge_response",
                "encrypted_challenge_verifier": encrypted_verifier.hex()
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            print("Challenge code verifier send.")
        
        elif message["type"] == "krf_retrieval":
            print("Extract KRF-i.")
            encrypted_krf_i = bytes.fromhex(message["encrypted_krf_i"])
            print("Decrypt KRF-i.")
            krf_i = decrypt_message(encrypted_krf_i)
            
            # Re-encrypt KRF-i with KRC's public key
            print("Re-encrypt KRF-i.")
            re_encrypted_krf_i = encrypt_message(krf_i, keys["krc_public_key"])
            response = {
                "type": "krf_response",
                "encrypted_krf_i": re_encrypted_krf_i.hex()
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            print("KRF-i send.")
        
    except Exception as e:
        error_response = {"status": "error", "message": str(e)}
        client_socket.send(json.dumps(error_response).encode('utf-8'))
    finally:
        client_socket.close()

#========================= Main =========================
def main():
    print(f"{KRA_ID} script has started executing.")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    server_socket.listen(5)
    print(f"{KRA_ID} will listening on {LISTEN_HOST}:{LISTEN_PORT}")
    
    while True:
        client_socket, _ = server_socket.accept()
        handle_client(client_socket)

if __name__ == "__main__":
    ENTITY_NAME = f"{KRA_ID}"  # Replace with the container's entity name (e.g., sender, receiver, krc, kra1, etc.)
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
            wait_for_no_trigger(SHARED_KEYS_FOLDER)

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
        main()

    except TimeoutError as e:
        print(f"[{ENTITY_NAME}] Error: {e}")
        exit(1)