from flask import Flask, request, jsonify
import socket
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import uuid
import time

#========================= Key Setup =========================
# Load keys directly
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Get the directory of the current script
script_dir = os.path.abspath(os.path.dirname(__file__))

# Paths for Sender's private and public keys (in the same level as script)
sender_private_key_path = os.path.join(script_dir, "keys", "sender_private.pem")
sender_public_key_path = os.path.join(script_dir, "keys", "sender_public.pem")

# Paths for Shared folder keys (parallel to the Sender folder)
shared_keys_dir = os.path.abspath(os.path.join(script_dir, "./Shared/keys"))
receiver_public_key_path = os.path.join(shared_keys_dir, "receiver_public.pem")
krc_public_key_path = os.path.join(shared_keys_dir, "krc_public.pem")

kra_public_key_paths = [
    os.path.join(shared_keys_dir, f"kra{i}_public.pem") for i in range(1, 6)
]

# # Debug print to confirm paths
# print("Sender Private Key Path:", sender_private_key_path)
# print("Sender Public Key Path:", sender_public_key_path)
# print("Receiver Public Key Path:", receiver_public_key_path)
# print("KRC Public Key Path:", krc_public_key_path)
# print("KRA Public Key Paths:", kra_public_key_paths)

# Load keys with error checking
try:
    sender_private_key = load_private_key(sender_private_key_path)
    sender_public_key = load_public_key(sender_public_key_path)

    receiver_public_key = load_public_key(receiver_public_key_path)
    krc_public_key = load_public_key(krc_public_key_path)

    kra_public_keys = [load_public_key(path) for path in kra_public_key_paths]

except FileNotFoundError as e:
    raise FileNotFoundError(f"Key file not found: {e}")

RECEIVERHOST = "192.168.1.12"

#========================= Utility Functions =========================
# Generate session key (AES key)
def generate_session_key():
    return os.urandom(32)  # AES 256-bit key

# Encrypt message with session key
def encrypt_plaintext(plaintext, session_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(plaintext.encode()) + encryptor.finalize()
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
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # Ensure data is padded to a multiple of block size (16 bytes for AES)
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
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
        print("!!!!!!!!!!DEBUG!!!!!!!!!!!")
        print("session key original:",session_key)
        print("iv:",iv)
    except Exception as e:
        print("Error encrypting plaintext message:", e)
        raise

    try:
        # Generate KRF
        krf = generate_krf(session_key, krc_public_key, kra_public_keys, receiver_public_key, session_id)
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

def test_assemble_krf(session_key, num_agents, si_values, sr,sgn):
    """
    Test the reconstruction of the session key and intermediate XOR states.
    """
    print("\n--- Testing KRF Assembly ---")
    print(f"Session Key (Original): {session_key.hex()}")
    print("Si Values and Sr:")
    for i, si in enumerate(si_values):
        print(f"  S_{i+1}: {si.hex()}")
    print(f"  Sr: {sr.hex()}")

    # Verify Sr calculation
    computed_sr = session_key
    for si in si_values:
        computed_sr = xor(computed_sr, si)
    print(f"Computed Sr: {computed_sr.hex()}")
    print("Sr Match:", computed_sr == sr)

    # Verify full session key reconstruction
    reconstructed_key = sr
    for si in si_values:
        reconstructed_key = xor(reconstructed_key, si)
    print(f"Reconstructed Session Key: {reconstructed_key.hex()}")
    print("Session Key Match:", session_key == reconstructed_key)

    # Verify intermediate XOR
    intermediate_xor = si_values[0]
    for si in si_values[1:]:
        intermediate_xor = xor(intermediate_xor, si)
    print(f"Intermediate XOR of Si: {intermediate_xor.hex()}")
    print("Intermediate XOR Match with Sr:", intermediate_xor == sr)
    print("SGN:",sgn)

# Generate KRF
def generate_krf(session_key, krc_public_key, kra_public_keys, receiver_public_key, session_id):
    print("Generating KRF...")
    print("DEBUG: Session Key:", session_key.hex())
    krf = {}
    num_kras = len(kra_public_keys)  # Number of KRAs (should be 5)
    timestamp = int(time.time())  # Current timestamp

    # Generate Si values for KRAs
    si_values = [os.urandom(32) for _ in range(num_kras)]
    sr = session_key  # Start with the session key
    for si in si_values:
        sr = xor(sr, si)  # Compute Sr such that XOR(Si, ..., Sr) = session_key

    print("Si Values and Sr:")
    for i, si in enumerate(si_values, start=1):
        print(f"  S_{i}: {si.hex()}")
    print(f"  Sr: {sr.hex()}")

    # Generate Ri for SGN calculation
    ri_values = [os.urandom(16) for _ in range(num_kras + 1)]  # Include receiver
    sgn = ri_values[0]
    for ri in ri_values[1:]:
        sgn = xor(sgn, ri)  # SGN = R1 XOR R2 XOR ... Rn

    # Construct KRF-i and TT-i for each KRA
    for i, (kra_key, si) in enumerate(zip(kra_public_keys, si_values), start=1):
        tti = xor(si, sgn)  # TTi = Si XOR SGN
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
    test_assemble_krf(session_key, num_kras, si_values, sr,sgn)
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

#========================= Test Payload ===========================
# def save_payload_to_file(payload, filename="payload.json"):
#     """
#     Save the given payload to a file in JSON format.

#     Args:
#         payload (dict): The payload to save.
#         filename (str): The name of the file to save the payload to. Defaults to "payload.json".
#     """
#     try:
#         # Ensure all bytes are converted to a JSON-serializable format
#         serialized_payload = {
#             key: (value.hex() if isinstance(value, bytes) else value)
#             for key, value in payload.items()
#         }

#         # Write serialized payload to a file
#         with open(filename, "w") as file:
#             json.dump(serialized_payload, file, indent=4)
#         print(f"Payload saved to {filename}")
#     except Exception as e:
#         print(f"Error saving payload to file: {e}")
#         raise

#========================= Session Manager =========================
current_session = {
    "session_id": None,
    "session_key": None
}

#========================= Flask Server =========================
app = Flask(__name__)

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
            plaintext, receiver_public_key, krc_public_key
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
        # print("Payload:", json.dumps(payload, indent=4))
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
        # print("Payload:", json.dumps(payload, indent=4))

    # disable after TEST PHASE!!!
    # save_payload_to_file(payload)

    # Send payload to Receiver
    datas = json.dumps(payload).encode("utf-8")
    response = send_to_receiver(datas)
    return jsonify({"response": response.decode()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
