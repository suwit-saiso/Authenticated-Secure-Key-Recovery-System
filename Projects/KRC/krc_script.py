import socket
import json
import struct
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os
import hashlib
import time

#========================= Setup =========================
# Load keys
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Get the directory of the current script
script_dir = os.path.abspath(os.path.dirname(__file__))

# Paths for KRC's private and public keys (in the same level as script)
krc_private_key_path = os.path.join(script_dir, "keys", "krc_private.pem")
krc_public_key_path = os.path.join(script_dir, "keys", "krc_public.pem")

# Paths for Shared folder keys (parallel to the Sender folder)
shared_keys_dir = os.path.abspath(os.path.join(script_dir, "../Shared/keys"))
receiver_public_key_path = os.path.join(shared_keys_dir, "receiver_public.pem")

kra_public_key_paths = [
    os.path.join(shared_keys_dir, f"kra{i}_public.pem") for i in range(1, 6)
]

# Load keys with error checking
try:
    krc_private_key = load_private_key(krc_private_key_path)
    krc_public_key = load_public_key(krc_public_key_path)

    receiver_public_key = load_public_key(receiver_public_key_path)

    kra_public_keys = [load_public_key(path) for path in kra_public_key_paths]
except FileNotFoundError as e:
    raise FileNotFoundError(f"Key file not found: {e}")

# Store KRA challenge verifiers
kra_challenge_verifiers = {}

# Helper funtions
def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

# Generate PKCE challenge code
def generate_pkce_challenge():
    challenge_code = os.urandom(32)
    challenge_verifier = hashlib.sha256(challenge_code).digest()
    return challenge_code, challenge_verifier

#====================== Core Functions ======================
# Function to receive and decrypt the request
def receive_and_decrypt_request(encrypted_request):
    decrypted_request = krc_private_key.decrypt(
        encrypted_request,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Decode the JSON-like structure from the request
    request = json.loads(decrypted_request.decode())
    krf = request['krf']
    requester_challenge_verifier = request['challenge_verifier']
    request_session_id = request['session_id']
    request_timestamp = request['timestamp']
    
    return krf, requester_challenge_verifier, request_session_id, request_timestamp

# Function to decrypt the KRF and validate the request
def decrypt_krf_and_validate_request(krf, request_session_id, request_timestamp):
    # Step: Decrypt session info
    encrypted_session_info = krf["session_info"]
    session_info_decrypted = krc_private_key.decrypt(
        encrypted_session_info,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    session_info = json.loads(session_info_decrypted.decode())
    krf_session_id = session_info["session_id"]
    krf_timestamp = session_info["timestamp"]
    
    # Step: Validate session and check timestamp
    if krf_session_id != request_session_id or abs(request_timestamp - krf_timestamp) > 600:
        raise ValueError("Invalid session or expired request.")
    print(f"Session ID: {krf_session_id}, Timestamp: {krf_timestamp}")

    return krf

# Verify the requester using PKCE-like challenge <-useful?
def verify_requester(challenge_code, requester_challenge_verifier):
    hashed_challenge_code = hashlib.sha256(challenge_code).digest()
    if hashed_challenge_code != requester_challenge_verifier:
        raise ValueError("Challenge verification failed.")
    return "Requester verified successfully."

#====================== Key Recovery Process ======================
# Function to distribute KRF-i and perform PKCE-like challenge with KRAs
def distribute_krf_to_kras(krf, kra_public_keys):
    encrypted_krf_i_list = []
    
    # Distribute KRF-i and perform PKCE-like challenge
    for i, kra_public_key in enumerate(kra_public_keys):
        try:
            # Generate challenge for each KRA
            challenge_code, challenge_verifier = generate_pkce_challenge()
            kra_challenge_verifiers[f"KRA-{i}"] = challenge_verifier  # Store verifier for validation later

            # Send the challenge code to KRA-i
            send_to_kra(i, kra_public_key.encrypt(
                challenge_code,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ))

            # Wait for the challenge verifier from KRA-i
            kra_response = receive_from_kra(i)
            kra_challenge_verifier = kra_response["challenge_verifier"]

            # decrypt challenge verifier
            inner_kra_challenge_verifier = krc_private_key.decrypt(
                kra_challenge_verifier,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Compare challenge verifiers
            if inner_kra_challenge_verifier != challenge_verifier:
                print(f"KRA-{i} verification failed.")
                handle_failed_kra(i)  # Handle failure scenario
                continue

            # If KRA verification succeeds, send KRF-i to KRA
            krf_i_encrypted = krf[f"KRF-{i}"]
            # Decrypt the outer layer
            inner_encrypted_data = krc_private_key.decrypt(
                krf_i_encrypted,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            # Forward the inner encrypted data to the responsible KRA
            send_to_kra(i, inner_encrypted_data)

            # Wait for KRA to return the KRF-i decrypted and re-encrypted with KRC's public key
            encrypted_krf_i = receive_from_kra(i)
            encrypted_krf_i_list.append(encrypted_krf_i)  # Collect the encrypted KRF-i part
            
        except Exception as e:
            print(f"Error communicating with KRA-{i}: {str(e)}")
            handle_failed_kra(i)

    # Check if all KRF-i parts are collected
    if len(encrypted_krf_i_list) != len(kra_public_keys):
        print("Not all KRF-i parts were collected, initiating failure handling.")
        handle_kra_failure()  # Handle recovery for missing parts
    
    return encrypted_krf_i_list


# Collect key shares from KRAs and assemble session key
def collect_key_shares_and_assemble(encrypted_krf_i_list):
    key_shares = []
    for encrypted_krf_i in encrypted_krf_i_list:
        # Decrypt KRF_i
        krf_i = krc_private_key.decrypt(
            encrypted_krf_i,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        krf_i_data = json.loads(krf_i.decode())
        key_shares.append(krf_i_data["Si"])
    
    # Assemble session key using XOR of all key shares
    session_key = key_shares[0]
    for share in key_shares[1:]:
        session_key = xor(session_key, share)
    
    return session_key

# Encrypt the session key for the receiver and return it
def encrypt_session_key(session_key):
    encrypted_session_key = receiver_public_key.encrypt(
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
    host = "0.0.0.0"
    port = 5003 + kra_index  # Each KRA gets a unique port starting from 5003.
    
    try:
        # Create a socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))  # Connect to the KRA server
            
            # Prepare data
            message = json.dumps({"encrypted_data": encrypted_data.hex()})
            
            # Send the length of the message first
            message_length = len(message).to_bytes(4, 'big')
            sock.sendall(message_length + message.encode('utf-8'))
            
            # Wait for a response
            response_length = int.from_bytes(sock.recv(4), 'big')
            response_data = sock.recv(response_length).decode('utf-8')
            
        # Return the response
        return json.loads(response_data)
    except Exception as e:
        raise ValueError(f"Failed to send data to KRA-{kra_index}: {str(e)}")

def receive_from_kra(kra_index):
    """
    Receive data from a KRA using a socket connection.
    """
    host = "0.0.0.0"
    port = 5003 + kra_index  # Each KRA gets a unique port starting from 5003.
    
    try:
        # Create a socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))  # Connect to the KRA server
            
            # Request data (you might need to define a specific request format)
            message = json.dumps({"action": "retrieve"})
            message_length = len(message).to_bytes(4, 'big')
            sock.sendall(message_length + message.encode('utf-8'))
            
            # Wait for a response
            response_length = int.from_bytes(sock.recv(4), 'big')
            response_data = sock.recv(response_length).decode('utf-8')
        
        # Return the response
        return json.loads(response_data)
    except Exception as e:
        raise ValueError(f"Failed to receive data from KRA-{kra_index}: {str(e)}")

# Function to handle individual KRA failures
def handle_failed_kra(kra_index, attempt=1, max_retries=3):
    if attempt > max_retries:
        print(f"KRA-{kra_index} failed after {max_retries} retries.")
        return False
    print(f"Retrying communication with KRA-{kra_index} (Attempt {attempt}/{max_retries})...")
    return True  # Retry logic or fallback mechanism

# Function to handle failure in the overall KRA key shares collection
def handle_kra_failure():
    print("Handling overall KRA failure for missing KRF-i parts.")
    # Fallback mechanism for missing parts or initiate recovery process
    # Implement SFM-KRS specific recovery (e.g., redundant shares or recovery mechanism)
    pass


def receive_request(client_socket):
    try:
        # Receive data
        data = client_socket.recv(4096)
        if not data:
            return
        encrypted_request = bytes.fromhex(data['encrypted_request'])
        # Step 1: Receive and decrypt the request
        krf, requester_challenge_verifier, request_session_id, request_timestamp = receive_and_decrypt_request(encrypted_request)
        krf_data = decrypt_krf_and_validate_request(krf, request_session_id, request_timestamp)

        # Step 2: Distribute KRF-i to KRAs and collect encrypted KRF-i responses
        encrypted_krf_i_list = distribute_krf_to_kras(krf_data, kra_public_keys)

        # Step 3: Assemble the session key from KRF-i parts
        session_key = collect_key_shares_and_assemble(encrypted_krf_i_list)

        # Step 4: Encrypt the session key and send it back to the Receiver
        encrypted_session_key = encrypt_session_key(session_key)
        client_socket.send(json.dumps(encrypted_session_key).encode('utf-8'))

    except Exception as e:
        error_response = {"status": "error", "message": str(e)}
        client_socket.send(json.dumps(error_response).encode('utf-8'))
    finally:
        client_socket.close()

#========================= Main =========================
def main():
    Receiver_PORT = 5001
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", Receiver_PORT))
    server_socket.listen(5)
    print(f"Receiver listening on port {Receiver_PORT}")
    
    while True:
        client_socket, _ = server_socket.accept()
        receive_request(client_socket)

if __name__ == "__main__":
    main()
