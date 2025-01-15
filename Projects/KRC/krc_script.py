import socket
import json
# import struct
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
# import time

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
shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
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

#============================= Helper funtions ===================================
def xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

# Generate PKCE challenge code
def generate_pkce_challenge():
    challenge_code = os.urandom(32)
    challenge_verifier = hashlib.sha256(challenge_code).digest()
    return challenge_code, challenge_verifier

# Decrypt the data using the AES key and iv (AES)
def decrypt_data(data, AES_key, iv):
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
    # decrypt the recovery request with KRC's privat key
    decrypted_request = krc_private_key.decrypt(
        encrypted_request,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Decode the JSON-like structure from the request
    request = json.loads(decrypted_request.decode())
    requester_challenge_verifier = request['challenge_verifier']
    request_session_id = request['session_id']
    request_timestamp = request['timestamp']

    if isinstance(requester_challenge_verifier, str):
            requester_challenge_verifier = bytes.fromhex(requester_challenge_verifier)

    print("Start decrypt AES key.")
    # decrypt the AES key with KRC's privat key
    decrypted_AES_key = krc_private_key.decrypt(
        encrypted_AES_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # decrypt the KRF with AES key and iv_aes
    print("Start decrypt KRF.")
    krf = decrypt_data(encrypted_krf, decrypted_AES_key, iv_aes)

    print("Finish decrypting request.")
    return krf, requester_challenge_verifier, request_session_id, request_timestamp

# Function to decrypt the KRF and validate the request
def decrypt_krf_and_validate_request(krf, request_session_id, request_timestamp):
    try:
        # Step: Decrypt session info
        print("Starting to decrypt KRF informations.")
        
        # Step 1: Parse the KRF JSON
        try:
            krf = json.loads(krf)  # Convert JSON string to a dictionary
            print("KRF successfully parsed:", type(krf), krf.keys())  # Debug parsed object
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            raise ValueError("Failed to parse KRF JSON.") from e
        
        # Step 2: Extract 'OtherInformation' and parse if necessary
        try:
            encrypted_other_info = krf["OtherInformation"]
            print("OtherInformation found:", encrypted_other_info)

            # Parse if OtherInformation is a JSON string
            if isinstance(encrypted_other_info, str):
                encrypted_other_info = json.loads(encrypted_other_info)

            if "Info" not in encrypted_other_info:
                raise KeyError("Missing 'Info' key in 'OtherInformation'.")
        except KeyError as e:
            print(f"Key error: {e}")
            raise ValueError("Invalid KRF structure. Missing required keys.") from e
        except json.JSONDecodeError as e:
            print(f"JSON parsing error for 'OtherInformation': {e}")
            raise ValueError("Failed to parse 'OtherInformation' JSON.") from e

        # Step 3: Validate 'Info' hex string
        try:
            hex_string = encrypted_other_info["Info"]
            encrypted_session_info = bytes.fromhex(hex_string)
            print("Hex to bytes conversion successful!")
        except ValueError as e:
            print(f"Hex decoding error: {e}")
            raise ValueError("Failed to decode 'Info' hex string to bytes.") from e
        
        # Step 4: Decrypt session info
        try:
            print("Attempting to decrypt session info...")
            session_info_decrypted = krc_private_key.decrypt(
                encrypted_session_info,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print("Decryption successful!")
            session_info = json.loads(session_info_decrypted.decode())
            print("Session Info:", session_info)
        except Exception as e:
            print(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt or parse session info.") from e

        # Step 5: Validate session ID and timestamp
        try:
            krf_session_id = session_info["session_id"]
            krf_timestamp = session_info["timestamp"]

            print("Validating session and timestamp...")
            if krf_session_id != request_session_id or abs(request_timestamp - krf_timestamp) > 600:
                raise ValueError("Invalid session ID or expired timestamp.")
            print(f"Session ID: {krf_session_id}, Timestamp: {krf_timestamp}, validation complete.")
        except KeyError as e:
            print(f"Key error during validation: {e}")
            raise ValueError("Session info missing required keys.") from e

        return krf

    except ValueError as e:
        print(f"Validation error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error during KRF decryption and validation: {e}")
        raise

# Verify the requester using PKCE-like challenge 
def verify_requester(challenge_code, requester_challenge_verifier):
    hashed_challenge_code = hashlib.sha256(challenge_code).digest()
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
            return

        # Parse JSON string into a Python dictionary
        data = json.loads(data.decode("utf-8"))
        
        print('Receiving data from Requester.Try to validat request')
        encrypted_challenge = bytes.fromhex(data['encrypted_challenge_code'])
        # decrypt the challenge code with KRC's privat key
        decrypted_challenge = krc_private_key.decrypt(
            encrypted_challenge,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        print("Verifying requester with challenge code.")
        verification = verify_requester(decrypted_challenge, requester_challenge_verifier)
        if verification != "Requester verified successfully.":
            print("Authorization failed.")
            return "Authorization failed."
        
        print("Authorization successfully.")
        return "Authorization successfully."
    
    except Exception as e:
        error_response = {"status": "error", "message": str(e)}
        client_socket.send(json.dumps(error_response).encode('utf-8')) 

#====================== Key Recovery Process ======================
# Function to distribute KRF-i and perform PKCE-like challenge with KRAs
def distribute_krf_to_kras(krf, kra_public_keys):
    print("Start distributing KRF-i.")
    # KRF is a dict
    krf_i_list = [None] * len(kra_public_keys)  # Initialize list with None for tracking
    
    # Distribute KRF-i and perform PKCE-like challenge
    for i, kra_public_key in enumerate(kra_public_keys, start=1):
        try:
            print(f'Generating challenge for KRA-{i}')

            # Generate challenge for each KRA
            challenge_code, challenge_verifier = generate_pkce_challenge()

            # Send the challenge code to KRA-i
            encrypted_challenge_code = kra_public_key.encrypt(
                challenge_code,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print("prepare data to send KRA")
            # Prepare data
            payload_1 = {
            "encrypted_challenge_code": encrypted_challenge_code.hex(),
            "type": "challenge"
            }

            payload_json = json.dumps(payload_1)
            payload_bytes1 = payload_json.encode('utf-8')
            print("Payload size in bytes:", len(payload_bytes1))
            connection1 = send_to_kra(i, payload_bytes1)

            # Wait for the challenge verifier from KRA-i
            kra_response = receive_from_kra(i,connection1)
            print("Extracting challenge verifier.")
            if kra_response["type"] != "challenge_response":
                raise ValueError(f"Unexpected response type from KRA-{i}: {kra_response.get('type')}")         

            # decrypt challenge verifier
            encrypted_kra_challenge_verifier = bytes.fromhex(kra_response["encrypted_challenge_verifier"])
            print("Decrypting challenge verifier.")
            kra_challenge_verifier = krc_private_key.decrypt(
                encrypted_kra_challenge_verifier,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Compare challenge verifiers
            print("Comparing challenge verifier.")
            if kra_challenge_verifier != challenge_verifier:
                print(f"KRA-{i} verification failed.")
                if not handle_failed_kra(i, payload_1, challenge_verifier):
                    print(f"KRA-{i} permanently failed. Marking index as None.")
                    krf_i_list[i - 1] = None
                    continue

            # If KRA verification succeeds, send KRF-i to KRA
            print(f"KRA-{i} verification succeeds.")
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
            connection2 = send_to_kra(i, payload_bytes2)

            # Wait for KRA to return the KRF-i decrypted and re-encrypted with KRC's public key
            encrypted_krf_i = receive_from_kra(i,connection2)
            print(f"Extracting KRF-{i} from KRA.")
            if encrypted_krf_i["type"] != "krf_response":
                raise ValueError(f"Unexpected response type from KRA-{i}: {kra_response.get('type')}")
    
            re_encrypted_krf_i = bytes.fromhex(encrypted_krf_i["encrypted_krf_i"])
            # Decrypt re_encrypted_krf_i with KRC' privat key
            print("Decrypting re-encrypted KRF-i.")
            decrypted_krf_i = krc_private_key.decrypt(
                re_encrypted_krf_i,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            # Convert the decrypted KRF-i from bytes to JSON
            try:
                krf_i = json.loads(decrypted_krf_i.decode())  # Parse JSON from bytes
                print(f"KRF-{i} successfully decrypted and parsed.")
            except json.JSONDecodeError as e:
                print(f"Error parsing decrypted KRF-{i}: {e}")
                krf_i = None  # Handle invalid JSON appropriately, if needed

            krf_i_list[i - 1] = krf_i  # Save the parsed JSON result at the correct index

        except Exception as e:
            print(f"Error communicating with KRA-{i}: {e}")
            if not handle_failed_kra(i, None, None):
                print(f"KRA-{i} permanently failed due to exception. Marking index as None.")
                krf_i_list[i - 1] = None

    # Check if all KRF-i parts are collected
    if None in krf_i_list:
        print("Not all KRF-i parts were collected, initiating failure handling.")
        krf_i_list = handle_kra_failure(krf_i_list, krf)  # Handle recovery for missing parts

    print("KRF-i list successfully completed without problems.")
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

    # Extract and validate Si values
    for i, krf_i in enumerate(krf_i_list):
        if krf_i is None:
            print(f"[ERROR] KRF-{i + 1} is missing. Cannot assemble session key.")
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
            error_occurred = True

    # If any errors occurred, return None
    if error_occurred or len(key_shares) < len(krf_i_list):
        print("[ERROR] Session key assembly failed due to missing or invalid KRF-i parts.")
        return None

    # Assemble session key using XOR
    assembled_session_key = key_shares[0]
    for share in key_shares[1:]:
        assembled_session_key = xor(assembled_session_key, share)

    print("Session key successfully assembled.")
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
    host = f"192.168.1.{13 + int(kra_index)}"
    port = 5002 + kra_index  # Each KRA gets a unique port starting from 5003.
    
    try:
        # Create a socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.settimeout(10)  # Set a 10-second timeout
        sock.connect((host, port))  # Connect to the KRA server          
        sock.sendall(encrypted_data)
        print(f"send data to KRA-{kra_index}.")
        return sock
    except socket.timeout:
        print("Timeout while sending data to KRC")
    except Exception as e:
        print(f"Error sending to KRA-{kra_index}: {e}")

def receive_from_kra(kra_index,sock):
    """
    Receive data from a KRA using a socket connection.
    """
    try:
        response = sock.recv(1024)
        print(f"Response received from KRA-{kra_index}.")
        return json.loads(response.decode())
    except socket.timeout:
        print(f"Timeout while waiting for response from KRA-{kra_index}")
        return {"error": "Timeout"}
    except Exception as e:
        print(f"Error receiving from KRA-{kra_index}: {e}")
        return {"error": str(e)}
    finally:
        if sock:
            print(f"Closing connection after receiving data from KRA-{kra_index}.")
            sock.close()
    
# Function to handle individual KRA failures
def handle_failed_kra(kra_index, payload, challenge_verifier):
    attempt = 1
    max_retries = 3

    while attempt <= max_retries:
        print(f"Retrying communication with KRA-{kra_index} (Attempt {attempt}/{max_retries})...")

        # Send the payload to the KRA
        connection = send_to_kra(kra_index, payload)

        # Wait for the challenge verifier response from KRA
        kra_response = receive_from_kra(kra_index,connection)
        if kra_response.get("type") == "challenge_response":
            try:
                print(f"Extracting challenge verifier on attempt {attempt}...")
                encrypted_kra_challenge_verifier = bytes.fromhex(kra_response["encrypted_challenge_verifier"])

                # Decrypt the challenge verifier
                print(f"Decrypting challenge verifier on attempt {attempt}...")
                kra_challenge_verifier = krc_private_key.decrypt(
                    encrypted_kra_challenge_verifier,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

                # Compare challenge verifiers
                print(f"Comparing challenge verifier on attempt {attempt}...")
                if kra_challenge_verifier == challenge_verifier:
                    print(f"KRA-{kra_index} verification succeeded.")
                    return True  # Successfully verified
                else:
                    print(f"KRA-{kra_index} verification failed. Challenge verifiers do not match.")
            except Exception as e:
                print(f"Error during KRA-{kra_index} verification on attempt {attempt}: {e}")
        else:
            print(f"Invalid response type from KRA-{kra_index}. Expected 'challenge_response', got: {kra_response.get('type')}")

        # Increment attempt count
        attempt += 1

    # If all retries are exhausted
    print(f"KRA-{kra_index} failed after {max_retries} retries.")
    return False

# Function to handle failure in the overall KRA key shares collection
def handle_kra_failure(krf_i_list, krf):
    print("Handling overall KRA failure for missing KRF-i parts.")

    # Step 1: Extract and validate SGN values
    sgn_values = [bytes.fromhex(krf_i["SGN"]) for krf_i in krf_i_list if krf_i is not None]

    if not sgn_values:  # Case 1: All KRF-i are missing
        print("[WARNING] All KRF-i parts are missing. Reconstruction is not possible.")
        return krf_i_list  # Leave list as it is (with None values)

    # Count occurrences of each SGN
    sgn_counts = {}
    for sgn in sgn_values:
        sgn_counts[sgn] = sgn_counts.get(sgn, 0) + 1

    # Identify the most common SGN
    most_common_sgn = max(sgn_counts, key=sgn_counts.get)
    print(f"Most common SGN identified: {most_common_sgn.hex()} (count: {sgn_counts[most_common_sgn]})")

    # Filter out mismatched KRF-i parts
    for i, krf_i in enumerate(krf_i_list):
        if krf_i and bytes.fromhex(krf_i["SGN"]) != most_common_sgn:
            print(f"[WARNING] Mismatched SGN in KRF-{i + 1}. Marking as missing.")
            krf_i_list[i] = None  # Mark mismatched KRF-i as missing

    # Step 2: Identify missing KRF-i parts
    missing_indices = [i for i, krf_i in enumerate(krf_i_list) if krf_i is None]
    print(f"Missing KRF-i indices: {missing_indices}")

    # Step 3: Recreate missing KRF-i parts
    for i in missing_indices:
        try:
            # Retrieve and decrypt the corresponding TT-i value
            outer_encrypted_TTi = krf[f"TT-{i + 1}"]  # i + 1 corresponds to KRA-1 to KRA-5
            if isinstance(outer_encrypted_TTi, str):
                print("Parsing outer_encrypted_TTi JSON.")
                outer_encrypted_TTi = json.loads(outer_encrypted_TTi)

            encrypted_TTi = bytes.fromhex(outer_encrypted_TTi["TTi"])  # Convert hex string to bytes
            TTi = krc_private_key.decrypt(
                encrypted_TTi,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # Debug: Verify decrypted TT-i
            print(f"Decrypted TT-{i + 1}: {TTi.hex()}")

            # Calculate Si using XOR
            Si = xor(most_common_sgn, TTi)  # S_i = TTi XOR SGN

            # Debug: Verify reconstructed Si
            print(f"Reconstructed S_{i + 1}: {Si.hex()}")

            # Recreate KRF-i as a dictionary with hex strings
            recreated_krf_i = {"Si": Si.hex(), "SGN": most_common_sgn.hex()}
            print(f"Recreated KRF-{i + 1}")

            # Save the recreated KRF-i in the list
            krf_i_list[i] = recreated_krf_i
        except Exception as e:
            print(f"[ERROR] Failed to reconstruct KRF-{i + 1}: {e}")

    # Step 4: Return the updated KRF-i list
    print("KRF-i list successfully completed.")
    return krf_i_list

def receive_request(client_socket):
    try:
        # Phase 1: Receive data
        print("Receiving data...")
        length = int.from_bytes(client_socket.recv(4), byteorder="big")
        data = client_socket.recv(length)
        if not data:
            raise ValueError("No data received from client.")
        
        # Parse the received data
        data = json.loads(data.decode("utf-8"))
        print("Loaded data from requester.")
        
        encrypted_request = bytes.fromhex(data.get("encrypted_request", ""))
        encrypted_krf = bytes.fromhex(data.get("encrypted_krf", ""))
        encrypted_AES_key = bytes.fromhex(data.get("encrypted_AES_key", ""))
        iv_aes = bytes.fromhex(data.get("iv_aes", ""))

        print("Beginning Phase 1: Processing request.")
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
        authorization = client_validation(client_socket, requester_challenge_verifier)
        if authorization != "Authorization successfully.":
            raise ValueError("Requester validation failed: Authentication error.")

        requester_validation = {"response": "Authenticate successfully"}
        client_socket.send(json.dumps(requester_validation).encode('utf-8'))

        # Phase 3: Distribute KRF-i
        print("Beginning Phase 3: Distributing KRF-i.")
        krf_i_list = distribute_krf_to_kras(krf_data, kra_public_keys)

        # Phase 4: Assemble session key
        print("Beginning Phase 4: Assembling session key.")
        unfinished_session_key = collect_key_shares_and_assemble(krf_i_list)

        # Phase 5: Encrypt and send session key
        print("Beginning Phase 5: Encrypting and sending session key.")
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
        client_socket.close()

#========================= Main =========================
def main():
    KRC_PORT = 5002
    print("DEBUG: KRC script has started executing.")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("192.168.1.13", KRC_PORT))
    server_socket.listen(5)
    print(f"KRC listening on port {KRC_PORT}")
    
    while True:
        client_socket, _ = server_socket.accept()
        receive_request(client_socket)

if __name__ == "__main__":
    main()